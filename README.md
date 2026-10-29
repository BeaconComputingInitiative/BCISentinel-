# Beacon Computing Initiative — Orbital Sentinel v4.6.11-TRACE

Developer Seal: **CJB-DEV-2026**. Project seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX.

## Feature-preserving upgrade from v4.6.7-op2

Retains the existing **two passive Docker services**, Prometheus on localhost ports **9100/9101**, PyQt6 dashboard, frozen feed, station/AP tables, terminal stream, offline WPA-capture decryption dialog, automatic eligible monitor-mode interface selection, storage checks, and graceful shutdown. Capture interface is never reconfigured by this release.

Enhancements:
- Per-BSSID beacon counts, last signal, interval, TSF reset indicators, interarrival timing, a limited rolling beacon history, IE profile changes, and WPA/RSN advertisement.
- AP and station vendor labels from an OUI database copied locally from the host when available; randomized/local MACs are labelled as unknown.
- Associated AP BSSID and SSID for observed station traffic with **association_response_observed**, **traffic_observed**, or **unconfirmed** evidence categories. This is not authentication proof.
- Passive deauthentication/disassociation burst indicators and EAPOL counters. These indicators alone do **not** prove botnet compromise.
- Streaming per-AP beacon feature windows (`captures/ml/{role}_beacon_windows.jsonl`), wireless anomaly records (`{role}_indicators.jsonl`), and per-role SHA-256 checksums on graceful shutdown.
- Separate **offline** edge network intelligence: reads operator-provided normalized/Zeek JSONL flow and DNS records and optional local IoC JSON for periodic network callouts, NXDOMAIN/DGA-like activity, protocol/port mismatches, large ICMP, TCP SYN spikes, SMTP fanout, external scanning patterns, reputation matches, shared DDNS/new domains, and multiple DNS answers. Generates `flow_indicators.jsonl`, `flow_ml_features.jsonl`, summary JSON, and SHA-256 manifest.

## Limits — do not conflate two types of beacons

**802.11 Wi-Fi beacons** are AP management broadcasts and can be read without joining the network. **Botnet/C2 check-in beaconing** refers to periodic IP network connections and is **not observable from encrypted Wi-Fi beacons alone**. The optional flow analyzer requires independently obtained lawful edge telemetry from firewalls, flow collectors, routers, or DNS resolvers. `wlan1` monitoring does not supply that data.

Detection rules are configurable heuristics, not attribution or malware verdicts. DNS flux / shared dynamic DNS can be legitimate CDN/DDNS. Nearby vendors are inferred only for globally administered MAC OUIs present in the local manufacturer database. The release does not inject packets, decrypt Wi-Fi traffic, or run port scans. It does not automatically download threat feeds.

## Install — run as your normal desktop user

```bash
# BEACON COMPUTING INITIATIVE | CJB-DEV-2026
# Stop current v4.6.7-op2 capture before upgrading:
"$HOME/BCI/Docker Projects/orbital/orbitalctl.sh" stop
cd ~/Downloads
unzip -o BCI-Orbital-Sentinel-v4.6.11-TRACE.zip
cd BCI-Orbital-Sentinel-v4.6.11-TRACE
sha256sum -c SHA256SUMS
bash install_orbital.sh
ORBITAL="$HOME/BCI/Docker Projects/orbital/orbitalctl.sh"
bash "$ORBITAL" test
bash "$ORBITAL" start
bash "$ORBITAL" metrics
bash "$ORBITAL" gui
```

**Never `sudo bash install_orbital.sh`**; Docker permission prompts are handled by the control script. The installed directory with spaces is intentional and existing captures are preserved.

## Optional external telemetry import

```bash
# Review help and permitted fields; supply your OWN authorized edge logs.
bash "$ORBITAL" flow-analyze --help
bash "$ORBITAL" flow-analyze \
  --flows /path/to/zeek_conn.jsonl \
  --dns /path/to/zeek_dns.jsonl \
  --ioc /path/to/local_ioc.json \
  --out-dir "$HOME/BCI/Docker Projects/orbital/captures/flow_intel"
```

Inputs: Zeek JSONL `conn.log` fields `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `orig_bytes`, `resp_bytes`, etc.; Zeek JSONL `dns.log` with `query`, `rcode_name`, `answers`, `id.orig_h`; or normalized flow records with `ts`, `src_ip`, `dst_ip`, `dst_port`, `proto`, `bytes`, `service`, `tcp_flags`, `domain`, `dst_asn`. Local IoC JSON lists: `ips`, `domains`, `asns`, `new_domains`, `ddns_suffixes`.

Data set `label` remains `null`. ML exports pseudonymize host/AP identifiers within a session. Hashes prove file integrity against the accompanying manifest, not data correctness or authorship.

## Operational verification

```bash
bash "$ORBITAL" doctor
bash "$ORBITAL" status
bash "$ORBITAL" metrics
find "$HOME/BCI/Docker Projects/orbital/captures/ml" -name '*.jsonl' -type f
```

Container capture on your actual Kali adapter, vendor database availability, and PyQt6 GUI rendering must be verified after installation. All integration tests are local/synthetic until that validation.

## v4.6.11-TRACE — integrated GUI button and local API

The GUI adds **Hunt C2 Signatures**, a nonblocking request to
`http://127.0.0.1:9100/hunt_c2`. It performs a bounded review of already
observed wireless indicators and any **separately imported**, authorized
edge-flow intelligence. It does not inject probe frames, retune the radio,
spoof another adapter's MAC address, or infer C2 from high packet count.

The endpoint returns backward-compatible response keys (`success`, `report`,
`anomalies`, `sweep_channels`), along with the true `observed_channels` and
`mode`. `sweep_channels` is empty because no RF scan was performed by the C2
Hunt action. Metrics expose `bci_orbital_c2_hunts_total`; the GUI displays
this counter. Each successful hunt appends a pseudonymized ML feature record
in `captures/ml/sentinel_c2_hunts.jsonl`. On graceful shutdown the exporter
updates its role-specific SHA-256 manifest. Neither wireless indicators nor
flow heuristics are verified botnet labels.

CLI equivalent: `bash orbitalctl.sh hunt-c2`. The HTTP interface is bound
to `127.0.0.1` only. Both original passive services are unchanged.

## v4.6.11-TRACE — AP Auto-Trace integration

The **Auto-Trace AP** GUI button and `bash orbitalctl.sh trace [BSSID]` query
`GET /trace` at `127.0.0.1:9100`. The button uses a selected AP row when available,
or automatically selects the AP with the most **observed beacons**. The report
contains BSSID, SSID, channel, vendor, beacon count, advertised interval, RSSI,
security, and observed station relationship evidence. It does not claim a station
is authenticated based solely on a data-frame header. The passive trace does not
change channels, inject frames, deauthenticate clients, or connect to an AP.

Each successful trace appends a pseudonymized `captures/ml/sentinel_traces.jsonl`
record (or `discovery_traces.jsonl` when called on the discovery API). Raw station
MACs and BSSIDs appear in the operator-facing report, not in the ML JSONL. A
per-role SHA-256 manifest is finalized on graceful shutdown. Prometheus adds
`bci_orbital_traces_total` and `bci_orbital_trace_probes_sent_total`.

### Explicit active trace (optional, disabled by default)

The original user-supplied Auto-Trace snippet proposed automatically switching
channels and injecting 25 frames using another adapter's hardcoded MAC. This
release replaces that with a separate, opt-in `POST /trace/probe` action that
requires an observed target BSSID, affirmative authorization, the current radio
channel already matching the advertised AP channel, and a 60-second cooldown.
It sends at most two directed **probe requests**, using the selected monitor
interface's real MAC. It never sends deauthentication frames. A successful Scapy
call does not prove transmission or a response.

For a network you administer and are authorized to probe, stop capture then
start with `BCI_ACTIVE_PROBE_ENABLED=1 bash orbitalctl.sh start`, and use
`bash orbitalctl.sh trace-probe BSSID --authorize`. To return to disabled
mode, stop and restart without that environment variable. The active endpoint
is only served by the sentinel role on loopback. Ordinary `trace` and GUI use
passive mode regardless of this setting.

This is an operational integration; real wireless probe transmission and GUI
rendering require verification on the Kali adapter. No botnet attribution is
inferred from Wi-Fi beacon periodicity or station packet counts.
