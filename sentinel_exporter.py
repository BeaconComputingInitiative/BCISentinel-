#!/usr/bin/env python3
# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL EXPORTER v4.6.11-TRACE
# Developer Seal: CJB-DEV-2026
# Project Seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX
# SHA-256: see SHA256SUMS, generated for every release file
# ============================================================================
"""Original exporter functions preserved: AP/station tables, OUI vendors,
Prometheus counters, periodic on-disk state, and passive 802.11 capture.
Both services operate independently and write distinct state snapshots.
"""
import json
import hashlib
import secrets
import subprocess
from collections import deque
import os
import re
import signal
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

VERSION = '4.6.11-TRACE'
SEAL = 'CJB-DEV-2026'
IFACE = os.environ.get('BCI_IFACE', '').strip()
ROLE = os.environ.get('BCI_ROLE', 'sentinel').strip()
PORT = int(os.environ.get('PROMETHEUS_PORT', '9100'))
DATA_DIR = Path(os.environ.get('BCI_DATA_DIR', '/data'))
STATE_FILE = DATA_DIR / ('bci_state.json' if ROLE == 'sentinel' else 'bci_discovery_state.json')
metrics = {'frames_total': 0, 'aps_active': 0, 'stations_active': 0, 'rx_errors': 0,
           'beacons_total': 0, 'probe_responses_total': 0, 'deauth_frames_total': 0,
           'eapol_frames_total': 0, 'wireless_indicators_total': 0,
           'c2_hunts_executed': 0, 'traces_executed': 0, 'trace_probes_sent': 0}
active_aps: dict[str, dict] = {}
active_stations: dict[str, dict] = {}
lock = threading.RLock()
stop_event = threading.Event()
# One ephemeral per-process salt prevents direct correlation of exported AP IDs
# across unrelated sessions. The dashboard retains actual MACs for operator use.
ML_SALT = secrets.token_bytes(32)
ML_INTERVAL = max(5.0, float(os.getenv('BCI_ML_INTERVAL', '10')))
BEACON_HISTORY_LIMIT = 250
EVENTS_LIMIT = 200
indicators: list[dict[str, Any]] = []
recent_mgmt: dict[str, deque[float]] = {}
ml_last_export: dict[str, int] = {}
ml_pending: list[dict[str, Any]] = []
last_probe_monotonic = 0.0
probe_lock = threading.Lock()
ACTIVE_PROBE_ENABLED = os.getenv('BCI_ACTIVE_PROBE_ENABLED', '0') == '1'



def _normalize_mac(mac: str | None) -> str:
    return (mac or '').upper()


def _is_unicast(mac: str | None) -> bool:
    try:
        raw = bytes.fromhex((mac or '').replace(':', '').replace('-', ''))
        return len(raw) == 6 and not (raw[0] & 1) and raw != b'\x00' * 6
    except ValueError:
        return False


def _locally_administered(mac: str | None) -> bool:
    try:
        return bool(int((mac or '')[:2], 16) & 2)
    except ValueError:
        return False


def load_oui_lookup() -> dict[str, str]:
    """Support IEEE (hex) records and Wireshark manuf prefix records."""
    result: dict[str, str] = {}
    paths = [os.getenv('BCI_OUI_FILE', ''), str(DATA_DIR / 'vendor_oui.txt'), '/usr/share/ieee-data/oui.txt',
             '/usr/share/wireshark/manuf', '/usr/share/wireshark/wiresharkOUI.txt',
             '/var/lib/ieee-data/oui.txt', 'oui.txt']
    for path in paths:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding='utf-8', errors='replace') as stream:
                for line in stream:
                    if '(hex)' in line:
                        prefix, vendor = line.split('(hex)', 1)
                        key = re.sub(r'[^A-F0-9]', '', prefix.upper())[:6]
                    else:
                        fields = line.split(None, 2)
                        if len(fields) < 2 or fields[0].startswith('#'):
                            continue
                        key = re.sub(r'[^A-F0-9]', '', fields[0].split('/')[0].upper())[:6]
                        vendor = fields[2] if len(fields) > 2 else fields[1]
                    if len(key) == 6:
                        result[key] = vendor.strip()
            if result:
                print(f'[BCI] Loaded {len(result)} vendor prefixes from {path}', flush=True)
                break
        except OSError as exc:
            print(f'[BCI][WARN] OUI lookup skipped {path}: {exc}', flush=True)
    if not result:
        print('[BCI][WARN] No OUI database found: vendor names may be unavailable', flush=True)
    return result


OUI_DB = load_oui_lookup()


def get_vendor(mac: str) -> str:
    # Locally administered MACs are not reliable manufacturer identifiers.
    if not _is_unicast(mac):
        return 'Not a unicast device address'
    if _locally_administered(mac):
        return 'Randomized/local MAC (vendor unverified)'
    clean = re.sub(r'[^A-F0-9]', '', mac.upper())
    return OUI_DB.get(clean[:6], 'Unknown (OUI database missing or unlisted)')


def _iter_ies(pkt: Any, Dot11Elt: Any):
    elt = pkt.getlayer(Dot11Elt)
    for _ in range(128):
        if elt is None:
            break
        try:
            yield int(getattr(elt, 'ID', -1)), bytes(getattr(elt, 'info', b''))
        except (TypeError, ValueError):
            pass
        elt2 = elt.payload.getlayer(Dot11Elt) if getattr(elt, 'payload', None) is not None else None
        if elt2 is elt:
            break
        elt = elt2


def _get_ssid_channel(pkt: Any, Dot11Elt: Any) -> tuple[str, str]:
    ssid, channel = '', 'unknown'
    for ident, info in _iter_ies(pkt, Dot11Elt):
        if ident == 0 and info:
            ssid = info.decode('utf-8', errors='replace')[:80]
        elif ident == 3 and info:
            channel = str(info[0])
    return ssid, channel


def _rsn_akms(raw: bytes) -> set[int]:
    try:
        # RSN: Version(2) + Group suite(4) + pairwise count(2)
        if len(raw) < 8:
            return set()
        n = int.from_bytes(raw[6:8], 'little')
        pos = 8 + 4 * n
        if n > 64 or pos + 2 > len(raw):
            return set()
        m = int.from_bytes(raw[pos:pos+2], 'little')
        pos += 2
        if m > 64 or pos + 4*m > len(raw):
            return set()
        return {raw[pos+4*i+3] for i in range(m)
                if raw[pos+4*i:pos+4*i+3] == b'\x00\x0f\xac'}
    except (IndexError, ValueError):
        return set()


def _beacon_profile(pkt: Any, Dot11Elt: Any) -> dict[str, Any]:
    ies = list(_iter_ies(pkt, Dot11Elt))
    ssid, channel = _get_ssid_channel(pkt, Dot11Elt)
    # TIM (5) and CSA (37) normally vary; excluding them reduces false alerts.
    hashed = hashlib.sha256()
    for ident, info in ies:
        if ident in (5, 37) or ident < 0 or ident > 255:
            continue
        hashed.update(bytes([ident]) + len(info).to_bytes(2, 'big') + info)
    rsn = next((v for i, v in ies if i == 48), None)
    wpa = any(i == 221 and v.startswith(b'\x00\x50\xf2\x01') for i, v in ies)
    akm = _rsn_akms(rsn) if rsn else set()
    if 8 in akm and 2 in akm:
        security = 'WPA2-PSK/WPA3-SAE advertised'
    elif 8 in akm or 9 in akm:
        security = 'WPA3-SAE advertised'
    elif 18 in akm:
        security = 'OWE advertised'
    elif rsn is not None:
        security = 'RSN advertised (details unverified)'
    elif wpa:
        security = 'WPA advertised'
    else:
        security = 'No RSN/WPA advertised (not proof of open access)'
    return {'ssid': ssid, 'channel': channel, 'security': security,
            'ie_sha256': hashed.hexdigest(),
            'ie_count': len(ies)}


def _make_ap(mac: str) -> dict[str, Any]:
    return {'bssid': mac, 'ssid': '<Hidden SSID>', 'channel': 'unknown',
            'vendor': get_vendor(mac), 'packets': 0, 'beacons': 0,
            'probe_responses': 0, 'beacon_interval_tu': None,
            'rssi_last_dbm': None, 'beacon_gap_last_ms': None,
            'security': 'Unknown', 'ie_sha256': None,
            'profile_changes': 0, 'first_seen_utc': None, 'last_seen_utc': None,
            'tsf_last_us': None, 'tsf_discontinuities': 0, 'beacon_gap_mean_ms': None,
            'beacon_gap_jitter_ms': None, 'recent_beacons': [], '_gaps': deque(maxlen=32),
            '_last_beacon_monotonic': None,
            '_pending_ie_hash': None, '_pending_ie_n': 0}


def _make_station(mac: str) -> dict[str, Any]:
    return {'mac': mac, 'vendor': get_vendor(mac), 'ap': 'Unconfirmed',
            'ap_ssid': 'Unknown', 'association_evidence': 'unconfirmed',
            'packets': 0}


def _pseudonym(mac: str) -> str:
    return hashlib.sha256(ML_SALT + mac.encode('ascii', 'replace')).hexdigest()[:20]


def _raise_indicator_locked(event_type: str, bssid: str, detail: str, ts: str) -> None:
    event = {'timestamp_utc': ts, 'type': event_type, 'bssid': bssid,
             'detail': detail, 'assessment': 'review_required_not_botnet_attribution',
             'label': None}
    indicators.append(event)
    if len(indicators) > EVENTS_LIMIT:
        del indicators[:len(indicators) - EVENTS_LIMIT]
    ml_pending.append(event)
    if len(ml_pending) > 10000:
        del ml_pending[:len(ml_pending) - 10000]
    metrics['wireless_indicators_total'] += 1


def _mark_station_locked(mac: str, ap: str | None, evidence: str) -> None:
    mac, ap = _normalize_mac(mac), _normalize_mac(ap) if ap else None
    if not _is_unicast(mac):
        return
    st = active_stations.setdefault(mac, _make_station(mac))
    st['packets'] += 1
    rank = {'unconfirmed': 0, 'traffic_observed': 1, 'association_response_observed': 2}
    if ap and _is_unicast(ap) and rank[evidence] >= rank[st['association_evidence']]:
        st['ap'] = ap
        st['association_evidence'] = evidence
    if st['ap'] in active_aps:
        st['ap_ssid'] = active_aps[st['ap']]['ssid']
    metrics['stations_active'] = len(active_stations)


def packet_handler(pkt: Any) -> None:
    with lock:
        metrics['frames_total'] += 1
    try:
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11ProbeReq
        if not pkt.haslayer(Dot11):
            return
        frame = pkt[Dot11]
        transmitter = _normalize_mac(getattr(frame, 'addr2', None))
        bssid = _normalize_mac(getattr(frame, 'addr3', None))
        receiver = _normalize_mac(getattr(frame, 'addr1', None))
        ftype = int(getattr(frame, 'type', -1))
        subtype = int(getattr(frame, 'subtype', -1))
        timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        now = time.monotonic()

        if ftype == 0 and (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            if not _is_unicast(bssid):
                return
            profile = _beacon_profile(pkt, Dot11Elt)
            is_beacon = pkt.haslayer(Dot11Beacon)
            if is_beacon:
                beacon = pkt[Dot11Beacon]
                interval = getattr(beacon, 'beacon_interval', None)
                tsf = getattr(beacon, 'timestamp', None)
                try: interval = int(interval) if interval is not None else None
                except (ValueError, TypeError): interval = None
                try: tsf = int(tsf) if tsf is not None else None
                except (ValueError, TypeError): tsf = None
            else:
                interval = tsf = None
            signal_dbm = getattr(pkt, 'dBm_AntSignal', None)
            try: signal_dbm = int(signal_dbm)
            except (ValueError, TypeError): signal_dbm = None
            with lock:
                ap = active_aps.setdefault(bssid, _make_ap(bssid))
                ap['packets'] += 1
                ap['last_seen_utc'] = timestamp
                if ap['first_seen_utc'] is None:
                    ap['first_seen_utc'] = timestamp
                if profile['ssid']:
                    ap['ssid'] = profile['ssid']
                if profile['channel'] != 'unknown':
                    ap['channel'] = profile['channel']
                ap['security'] = profile['security']
                if signal_dbm is not None:
                    ap['rssi_last_dbm'] = signal_dbm
                newhash = profile['ie_sha256']
                oldhash = ap['ie_sha256']
                if oldhash is None:
                    ap['ie_sha256'] = newhash
                elif oldhash != newhash and is_beacon:
                    if ap['_pending_ie_hash'] == newhash:
                        ap['_pending_ie_n'] += 1
                    else:
                        ap['_pending_ie_hash'] = newhash
                        ap['_pending_ie_n'] = 1
                    if ap['_pending_ie_n'] >= 3:
                        ap['ie_sha256'] = newhash
                        ap['profile_changes'] += 1
                        _raise_indicator_locked('beacon_ie_profile_change', bssid,
                            'Three consecutive beacons advertised a changed IE profile', timestamp)
                        ap['_pending_ie_hash'], ap['_pending_ie_n'] = None, 0
                else:
                    ap['_pending_ie_hash'], ap['_pending_ie_n'] = None, 0
                if is_beacon:
                    metrics['beacons_total'] += 1
                    ap['beacons'] += 1
                    if interval and 1 <= interval <= 65535:
                        ap['beacon_interval_tu'] = interval
                    previous_tsf = ap['tsf_last_us']
                    if tsf is not None:
                        if previous_tsf is not None and tsf < previous_tsf and ap['beacons'] >= 3:
                            ap['tsf_discontinuities'] += 1
                            _raise_indicator_locked('ap_tsf_discontinuity', bssid,
                                'Advertised TSF moved backwards; reset or impersonation possible', timestamp)
                        ap['tsf_last_us'] = tsf
                    old = ap['_last_beacon_monotonic']
                    if old is not None:
                        gap = (now - old) * 1000
                        # Ignore long channel dwell/retune gaps when measuring cadence.
                        if 0 < gap <= 2000:
                            ap['beacon_gap_last_ms'] = round(gap, 2)
                            ap['_gaps'].append(gap)
                            gaps = list(ap['_gaps'])
                            ap['beacon_gap_mean_ms'] = round(sum(gaps) / len(gaps), 2)
                            if len(gaps) >= 2:
                                mu = sum(gaps)/len(gaps)
                                ap['beacon_gap_jitter_ms'] = round(
                                    (sum((v-mu)**2 for v in gaps)/len(gaps))**0.5, 2)
                    ap['_last_beacon_monotonic'] = now
                    ap['recent_beacons'].append({'timestamp_utc': timestamp,
                        'tsf_us': tsf, 'rssi_dbm': signal_dbm,
                        'interval_tu': interval, 'gap_ms': ap['beacon_gap_last_ms']})
                    if len(ap['recent_beacons']) > 24:
                        del ap['recent_beacons'][:-24]
                else:
                    metrics['probe_responses_total'] += 1
                    ap['probe_responses'] += 1
                for st in active_stations.values():
                    if st['ap'] == bssid:
                        st['ap_ssid'] = ap['ssid']
                metrics['aps_active'] = len(active_aps)
            return

        # 802.11 management frames: association success is observable, not cryptographic proof.
        if ftype == 0 and subtype in (1, 3) and _is_unicast(receiver) and _is_unicast(transmitter):
            status = getattr(pkt.payload, 'status', None)
            try:
                from scapy.layers.dot11 import Dot11AssoResp, Dot11ReassoResp
                layer = pkt.getlayer(Dot11AssoResp if subtype == 1 else Dot11ReassoResp)
                status = getattr(layer, 'status', status)
            except (ImportError, AttributeError):
                pass
            if status is not None and int(status) == 0:
                with lock:
                    _mark_station_locked(receiver, transmitter, 'association_response_observed')
            return

        if ftype == 2:
            fc = int(getattr(frame, 'FCfield', 0)) & 3
            with lock:
                if fc == 1:     # to-DS: station -> AP
                    _mark_station_locked(transmitter, receiver, 'traffic_observed')
                elif fc == 2:   # from-DS: AP -> station
                    _mark_station_locked(receiver, transmitter, 'traffic_observed')
        elif ftype == 0 and pkt.haslayer(Dot11ProbeReq):
            with lock:
                _mark_station_locked(transmitter, None, 'unconfirmed')

        if ftype == 0 and subtype in (10, 12):
            with lock:
                metrics['deauth_frames_total'] += 1
                # Directed management frames can carry BSSID in addr3.
                if _is_unicast(bssid):
                    times = recent_mgmt.setdefault(bssid, deque())
                    times.append(now)
                    while times and now - times[0] > 10.0:
                        times.popleft()
                    if len(times) == 12:
                        _raise_indicator_locked('management_disruption_burst', bssid,
                            'At least 12 deauthentication/disassociation frames seen in 10 seconds', timestamp)
        try:
            from scapy.layers.eap import EAPOL
            if pkt.haslayer(EAPOL):
                with lock:
                    metrics['eapol_frames_total'] += 1
        except ImportError:
            pass
    except Exception as exc:
        with lock:
            metrics['rx_errors'] += 1
        print(f'[BCI][WARN] packet parsing error: {type(exc).__name__}: {exc}', flush=True)



def snapshot() -> dict[str, Any]:
    with lock:
        return {
            'seal': SEAL, 'version': VERSION, 'role': ROLE, 'iface': IFACE,
            'updated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'metrics': dict(metrics),
            'aps': [{k:v for k,v in ap.items() if not k.startswith('_')} for ap in active_aps.values()],
            'stations': [dict(st) for st in active_stations.values()],
            'indicators': list(indicators),
            'visibility': 'passive_80211_metadata_only; encrypted C2 cannot be inspected',
        }


def write_snapshot(state: dict[str, Any], path: Path = STATE_FILE) -> None:
    # Atomic replace prevents GUI from reading half-written JSON.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f'.{path.stem}.', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(state, stream, separators=(',', ':'), ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _append_ml(path: Path, records: list[dict[str, Any]]) -> None:
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n')
        f.flush()
        os.fsync(f.fileno())


def flush_ml() -> None:
    # Feature windows are emitted incrementally, not one raw record per frame.
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with lock:
        rows = []
        for bssid, ap in active_aps.items():
            prior = ml_last_export.get(bssid, 0)
            current = ap['beacons']
            if current == prior:
                continue
            rows.append({'schema_version': 'bci.orbital.beacons.v1',
                         'record_type': 'beacon_window', 'timestamp_utc': now,
                         'ap_id': _pseudonym(bssid), 'vendor': ap['vendor'],
                         'channel': ap['channel'], 'security_advertised': ap['security'],
                         'beacons_since_last_window': current - prior,
                         'beacons_total': current, 'beacon_interval_tu': ap['beacon_interval_tu'],
                         'rssi_last_dbm': ap['rssi_last_dbm'],
                         'beacon_gap_last_ms': ap['beacon_gap_last_ms'],
                         'beacon_gap_mean_ms': ap['beacon_gap_mean_ms'],
                         'beacon_gap_jitter_ms': ap['beacon_gap_jitter_ms'],
                         'tsf_discontinuities': ap['tsf_discontinuities'],
                         'ie_sha256': ap['ie_sha256'], 'profile_changes': ap['profile_changes'],
                         'label': None, 'synthetic': False})
        pending = list(ml_pending)
        ml_pending.clear()
    events = [{**e, 'ap_id': _pseudonym(e['bssid'])} for e in pending]
    for e in events:
        e.pop('bssid', None)
    try:
        _append_ml(DATA_DIR / 'ml' / f'{ROLE}_beacon_windows.jsonl', rows)
        _append_ml(DATA_DIR / 'ml' / f'{ROLE}_indicators.jsonl', events)
        with lock:
            for bssid, ap in active_aps.items():
                ml_last_export[bssid] = ap['beacons']
    except OSError as exc:
        # Best-effort recoverability: do not silently discard event queue.
        with lock:
            ml_pending[:0] = pending
            metrics['rx_errors'] += 1
        print(f'[BCI][ERROR] ML export failure: {exc}', flush=True)


def finalize_ml_manifest() -> None:
    root = DATA_DIR / 'ml'
    if not root.exists():
        return
    rows = []
    for filename in (f'{ROLE}_beacon_windows.jsonl', f'{ROLE}_indicators.jsonl', f'{ROLE}_c2_hunts.jsonl', f'{ROLE}_traces.jsonl'):
        path = root / filename
        if path.exists():
            rows.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {filename}')
    (root / f'{ROLE}_SHA256SUMS').write_text('\n'.join(rows) + ('\n' if rows else ''), encoding='utf-8')


def state_flusher() -> None:
    last_ml = time.monotonic()
    while not stop_event.wait(1.5):
        try:
            write_snapshot(snapshot())
            if time.monotonic() - last_ml >= ML_INTERVAL:
                flush_ml()
                last_ml = time.monotonic()
        except OSError as exc:
            print(f'[BCI][ERROR] state persistence failed: {exc}', flush=True)
            with lock:
                metrics['rx_errors'] += 1
    try:
        write_snapshot(snapshot())
        flush_ml()
        finalize_ml_manifest()
    except OSError as exc:
        print(f'[BCI][ERROR] final state persistence failed: {exc}', flush=True)


def background_sniffer() -> None:
    try:
        from scapy.all import sniff
    except ImportError:
        print('[BCI][ERROR] Scapy not installed in the container', flush=True)
        stop_event.set()
        return
    while not stop_event.is_set():
        try:
            sniff(iface=IFACE, prn=packet_handler, store=False, timeout=2)
        except Exception as exc:
            with lock:
                metrics['rx_errors'] += 1
            print(f'[BCI][ERROR] sniff({IFACE}): {type(exc).__name__}: {exc}', flush=True)
            stop_event.wait(2)


def execute_c2_hunt() -> tuple[bool, dict[str, Any] | str]:
    """On-demand **passive** security-indicator review, not RF C2 attribution.

    Wi-Fi beacons are AP advertisements, not malware check-ins. This method
    does not change channels, inject frames, or connect to a foreign network.
    Actual C2-like IP/DNS evidence is available ONLY from independently
    supplied, authorized flow logs. The API contract stays compatible with
    the user-supplied GUI's /hunt_c2 response keys.
    """
    utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with lock:
        ap_index = {bssid: {k: ap.get(k) for k in ('ssid', 'channel', 'vendor')}
                    for bssid, ap in active_aps.items()}
        station_count = len(active_stations)
        observed_channels = sorted({str(ap['channel']) for ap in ap_index.values()
                                    if ap.get('channel') not in ('unknown', None)},
                                   key=lambda val: (not val.isdigit(), int(val) if val.isdigit() else val))
        wireless = list(indicators[-50:])
        beacon_count = int(metrics['beacons_total'])
    # Use only operator-provided edge telemetry from the independent local
    # analyzer. Never imply it was derived from encrypted Wi-Fi beacons.
    flow_path = DATA_DIR / 'flow_intel' / 'flow_summary.json'
    edge_summary = None
    if flow_path.is_file():
        try:
            if flow_path.stat().st_size > 2_000_000:
                return False, 'Edge-flow summary exceeds the maximum accepted size'
            with flow_path.open(encoding='utf-8') as handle:
                candidate = json.load(handle)
            if not isinstance(candidate, dict):
                return False, 'Edge-flow summary must contain a JSON object'
            edge_summary = candidate
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return False, f'Unable to load edge-flow summary: {type(exc).__name__}'
    anomalies = []
    for item in wireless:
        ap = ap_index.get(item.get('bssid', ''), {})
        anomalies.append({
            'mac': None, 'vendor': ap.get('vendor', 'Unverified'),
            'associated_ap': item.get('bssid'),
            'indicator': item.get('type', 'wireless_indicator'),
            'detail': item.get('detail', ''),
            'evidence_source': 'passive_80211_management',
            'classification': 'wireless_anomaly_not_c2_evidence',
        })
    flow_count = 0
    if edge_summary is not None:
        try:
            flow_count = max(0, int(edge_summary.get('events', 0)))
        except (ValueError, TypeError):
            flow_count = 0
    report = {
        'generated_at_utc': utc,
        'mode': 'passive_snapshot_no_transmissions',
        'sweep_channels': [],  # Nothing was transmitted or retuned.
        'observed_channels': observed_channels,
        'total_stations_analyzed': station_count,
        'aps_observed': len(ap_index),
        'beacons_observed': beacon_count,
        'suspicious_nodes_found': 0,  # No host attribution from RF metadata.
        'wireless_indicators_found': len(wireless),
        'flow_indicators_found': flow_count,
        'flow_evidence_available': edge_summary is not None,
        'flow_indicator_types': (edge_summary or {}).get('event_types', {}),
        'anomalies': anomalies,
        'finding': ('Wireless events require review. '
                    'C2-like flow evidence is from separately imported edge logs, '
                    'not Wi-Fi beacons.'),
        'ground_truth_botnet_labels': False,
    }
    # Automatic pseudonymized ML export: never write raw BSSID or station
    # identifiers to the training file.
    ml_record = {
        'schema_version': 'bci.orbital.c2hunt.v1',
        'record_type': 'c2_hunt_snapshot',
        'developer_seal': SEAL,
        'timestamp_utc': utc,
        'mode': report['mode'],
        'features': {key: report[key] for key in (
            'total_stations_analyzed', 'aps_observed', 'beacons_observed',
            'wireless_indicators_found', 'flow_indicators_found',
            'flow_evidence_available')},
        'label': None, 'synthetic': False,
    }
    try:
        _append_ml(DATA_DIR / 'ml' / f'{ROLE}_c2_hunts.jsonl', [ml_record])
    except OSError as exc:
        return False, f'Hunt audit export failed: {type(exc).__name__}'
    with lock:
        metrics['c2_hunts_executed'] += 1
    return True, report


def execute_auto_trace(target_bssid: str | None = None) -> tuple[bool, dict[str, Any] | str]:
    """Summarize an AP's observed activity and relationship evidence, without RF transmission.

    A requested BSSID must already exist in the passive observation inventory.
    Selecting the busiest AP is convenience, not a threat/risk ranking.
    """
    utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with lock:
        if not active_aps:
            return False, 'No observed access points yet. Capture beacons before running Auto-Trace.'
        if target_bssid:
            if not isinstance(target_bssid, str):
                return False, 'Invalid BSSID type.'
            key = _normalize_mac(target_bssid)
            if not _is_unicast(key) or key not in active_aps:
                return False, 'Target BSSID was not found in the passive observation inventory.'
        else:
            key = max(active_aps, key=lambda value: (
                int(active_aps[value].get('beacons', 0)),
                int(active_aps[value].get('packets', 0)), value))
        ap = dict(active_aps[key])
        related = [dict(st) for st in active_stations.values() if st.get('ap') == key
                   and st.get('association_evidence') != 'unconfirmed']
    # ML export is deliberately pseudonymized, unlike the operator-facing report.
    record = {
        'schema_version': 'bci.orbital.trace.v1',
        'record_type': 'ap_auto_trace',
        'developer_seal': SEAL,
        'timestamp_utc': utc,
        'mode': 'passive_no_transmission',
        'ap_id': _pseudonym(key),
        'features': {
            'channel': ap.get('channel'), 'vendor': ap.get('vendor'),
            'beacons_total': int(ap.get('beacons', 0)),
            'packets_total': int(ap.get('packets', 0)),
            'beacon_interval_tu': ap.get('beacon_interval_tu'),
            'rssi_last_dbm': ap.get('rssi_last_dbm'),
            'security_advertised': ap.get('security'),
            'beacon_ie_sha256': ap.get('ie_sha256'),
            'profile_changes': ap.get('profile_changes', 0),
            'stations_with_ap_evidence': len(related),
            'association_response_observed': sum(
                st.get('association_evidence') == 'association_response_observed'
                for st in related),
            'traffic_observed': sum(
                st.get('association_evidence') == 'traffic_observed' for st in related),
        },
        'related_station_ids': [_pseudonym(st['mac']) for st in related],
        'label': None,
        'synthetic': False,
    }
    try:
        _append_ml(DATA_DIR / 'ml' / f'{ROLE}_traces.jsonl', [record])
    except OSError as exc:
        return False, f'Auto-Trace audit export failed: {type(exc).__name__}: {exc}'
    with lock:
        metrics['traces_executed'] += 1
    report = {
        'generated_at_utc': utc, 'mode': 'passive_no_transmission',
        'target_bssid': key, 'target_ssid': ap.get('ssid', '<Hidden SSID>'),
        'channel': ap.get('channel', 'unknown'), 'vendor': ap.get('vendor', 'Unknown'),
        'total_ap_packets': int(ap.get('packets', 0)),
        'beacons_observed': int(ap.get('beacons', 0)),
        'beacon_interval_tu': ap.get('beacon_interval_tu'),
        'rssi_last_dbm': ap.get('rssi_last_dbm'),
        'security_advertised': ap.get('security', 'Unknown'),
        'beacon_ie_sha256': ap.get('ie_sha256'),
        'profile_changes': ap.get('profile_changes', 0),
        'associated_stations_count': len(related),
        'stations': [st['mac'] for st in related],  # backward-compatible operator view
        'station_evidence': [
            {'mac': st['mac'], 'vendor': st.get('vendor'),
             'association_evidence': st.get('association_evidence'),
             'ap_ssid': st.get('ap_ssid')} for st in related],
        'relationship_note': ('Observed association responses/traffic suggest an AP relationship; '
                              'this does not prove a currently authenticated connection.'),
        'risk_assessment': 'no_botnet_attribution_from_beacons',
        'channel_changed': False,
        'frames_transmitted': 0,
    }
    return True, report


def _monitor_radio_identity(iface: str) -> tuple[str, int] | None:
    """Read actual monitor interface MAC and channel; never use a hardcoded MAC."""
    try:
        result = subprocess.run(['iw', 'dev', iface, 'info'], capture_output=True,
                                text=True, check=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    mode, mac, channel = None, None, None
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == 'type':
            mode = parts[1]
        if len(parts) >= 2 and parts[0] == 'addr':
            mac = parts[1]
        if len(parts) >= 2 and parts[0] == 'channel':
            try:
                channel = int(parts[1])
            except ValueError:
                return None
    if mode != 'monitor' or not _is_unicast(mac) or channel is None:
        return None
    return mac, channel


def execute_explicit_probe(target_bssid: str, authorized: bool) -> tuple[bool, dict[str, Any] | str]:
    """Optional opt-in directed *probe request*, never a deauthentication frame.

    Requires explicit operator authorization, a previously seen AP, the current
    radio channel matching the AP's advertised channel, and a 60-second cooldown.
    Does not retune the radio or impersonate a different interface's MAC.
    """
    global last_probe_monotonic
    if ROLE != 'sentinel' or not ACTIVE_PROBE_ENABLED:
        return False, 'Active probe disabled. Set BCI_ACTIVE_PROBE_ENABLED=1 before starting Sentinel.'
    if authorized is not True:
        return False, 'Explicit operator authorization required.'
    if not isinstance(target_bssid, str):
        return False, 'Invalid BSSID.'
    bssid = _normalize_mac(target_bssid)
    if not _is_unicast(bssid):
        return False, 'Invalid BSSID.'
    with probe_lock:
        with lock:
            if bssid not in active_aps:
                return False, 'Target BSSID was not observed by Sentinel.'
            ap = dict(active_aps[bssid])
        if time.monotonic() - last_probe_monotonic < 60:
            return False, 'Probe cooldown active (60 seconds).'
        try:
            advertised_channel = int(ap['channel'])
        except (ValueError, TypeError, KeyError):
            return False, 'Cannot probe an AP with an unknown channel.'
        radio = _monitor_radio_identity(IFACE)
        if radio is None:
            return False, 'Unable to verify current monitor-radio identity.'
        radio_mac, tuned_channel = radio
        if tuned_channel != advertised_channel:
            return False, 'Radio is on a different channel. No channel changes were made.'
        try:
            from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
        except ImportError:
            return False, 'Scapy injection dependencies unavailable.'
        # Two gentle directed probes, not an undisclosed 25-frame burst.
        ssid = ap.get('ssid', '')
        ssid_bytes = ssid.encode('utf-8')[:32] if ssid and ssid != '<Hidden SSID>' else b''
        pkt = (RadioTap() /
               Dot11(type=0, subtype=4, addr1=bssid, addr2=radio_mac, addr3=bssid) /
               Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid_bytes))
        try:
            sendp(pkt, iface=IFACE, count=2, inter=0.5, verbose=False)
        except Exception as exc:
            return False, f'Explicit probe failed: {type(exc).__name__}: {exc}'
        last_probe_monotonic = time.monotonic()
        with lock:
            metrics['trace_probes_sent'] += 2
        return True, {'mode': 'explicit_authorized_probe', 'target_bssid': bssid,
                      'channel': tuned_channel, 'frames_transmitted': 2,
                      'response_confirmed': False,
                      'note': 'sendp success does not establish over-the-air delivery or response.'}


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith('/trace'):
            from urllib.parse import urlsplit, parse_qs
            parsed = urlsplit(self.path)
            if parsed.path != '/trace':
                self.send_error(404)
                return
            bssid = parse_qs(parsed.query).get('bssid', [None])[0]
            success, result = execute_auto_trace(bssid)
            data = json.dumps({'success': success, 'report' if success else 'error': result}, ensure_ascii=False).encode('utf-8')
            self.send_response(200 if success else 400)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == '/hunt_c2':
            success, result = execute_c2_hunt()
            response = {'success': success}
            response['report' if success else 'error'] = result
            data = json.dumps(response, ensure_ascii=False).encode('utf-8')
            self.send_response(200 if success else 503)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path not in ('/metrics', '/healthz'):
            self.send_error(404)
            return
        if self.path == '/healthz':
            data = b'ok\n'
        else:
            with lock:
                values = dict(metrics)
            data = (\
                '# HELP bci_orbital_frames_total Total captured 802.11 frames\n'
                '# TYPE bci_orbital_frames_total counter\n'
                f"bci_orbital_frames_total {values['frames_total']}\n"
                '# HELP bci_orbital_aps_active Discovered access points\n'
                '# TYPE bci_orbital_aps_active gauge\n'
                f"bci_orbital_aps_active {values['aps_active']}\n"
                '# HELP bci_orbital_stations_active Tracked stations\n'
                '# TYPE bci_orbital_stations_active gauge\n'
                f"bci_orbital_stations_active {values['stations_active']}\n"
                '# HELP bci_orbital_rx_errors_total Capture and parsing errors\n'
                '# TYPE bci_orbital_rx_errors_total counter\n'
                f"bci_orbital_rx_errors_total {values['rx_errors']}\n"
                '# TYPE bci_orbital_beacons_total counter\n'
                f"bci_orbital_beacons_total {values['beacons_total']}\n"
                '# TYPE bci_orbital_probe_responses_total counter\n'
                f"bci_orbital_probe_responses_total {values['probe_responses_total']}\n"
                '# TYPE bci_orbital_deauth_frames_total counter\n'
                f"bci_orbital_deauth_frames_total {values['deauth_frames_total']}\n"
                '# TYPE bci_orbital_eapol_frames_total counter\n'
                f"bci_orbital_eapol_frames_total {values['eapol_frames_total']}\n"
                '# TYPE bci_orbital_wireless_indicators_total counter\n'
                f"bci_orbital_wireless_indicators_total {values['wireless_indicators_total']}\n"
                '# HELP bci_orbital_c2_hunts_total On-demand passive hunt reviews\n'
                '# TYPE bci_orbital_c2_hunts_total counter\n'
                f"bci_orbital_c2_hunts_total {values['c2_hunts_executed']}\n"
                '# TYPE bci_orbital_traces_total counter\n'
                f"bci_orbital_traces_total {values['traces_executed']}\n"
                '# TYPE bci_orbital_trace_probes_sent_total counter\n'
                f"bci_orbital_trace_probes_sent_total {values['trace_probes_sent']}\n"
            ).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4' if self.path == '/metrics' else 'text/plain')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path != '/trace/probe':
            self.send_error(404)
            return
        try:
            n = int(self.headers.get('Content-Length', '0'))
            if n < 2 or n > 2048:
                self.send_error(413, 'Invalid request length')
                return
            body = json.loads(self.rfile.read(n))
            if not isinstance(body, dict):
                raise ValueError('Expected JSON object')
            success, result = execute_explicit_probe(body.get('bssid', ''),
                                                     body.get('authorized') is True)
        except (ValueError, TypeError, json.JSONDecodeError):
            success, result = False, 'Malformed probe request'
        data = json.dumps({'success': success, 'report' if success else 'error': result}).encode('utf-8')
        self.send_response(200 if success else 400)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        return


def main() -> int:
    if ROLE not in ('sentinel', 'discovery') or not IFACE or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", IFACE):
        print('[BCI][ERROR] Invalid BCI_ROLE or BCI_IFACE', flush=True)
        return 2
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        write_snapshot(snapshot())
    except OSError as exc:
        print(f'[BCI][ERROR] Cannot write {STATE_FILE}: {exc}', flush=True)
        return 3
    try:
        server = ThreadingHTTPServer(('127.0.0.1', PORT), MetricsHandler)
        server.timeout = 1
    except OSError as exc:
        print(f'[BCI][ERROR] Cannot bind 127.0.0.1:{PORT}: {exc}', flush=True)
        return 4
    def on_signal(signum: int, _frame: Any) -> None:
        print(f'[BCI] Signal {signum}; finalizing {ROLE}', flush=True)
        stop_event.set()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    t_flush = threading.Thread(target=state_flusher, name='state-flusher', daemon=False)
    t_sniff = threading.Thread(target=background_sniffer, name='packet-sniffer', daemon=True)
    t_flush.start()
    t_sniff.start()
    print(f'[BCI] READY role={ROLE} iface={IFACE} metrics=127.0.0.1:{PORT} state={STATE_FILE}', flush=True)
    try:
        while not stop_event.is_set():
            server.handle_request()
    finally:
        stop_event.set()
        t_flush.join(timeout=5)
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
