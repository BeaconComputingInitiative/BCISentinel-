#!/usr/bin/env python3
# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL FLOW INTELLIGENCE v4.6.8-op2
# Developer Seal: CJB-DEV-2026
# Project Seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX
# SHA-256: see SHA256SUMS for this file
# ============================================================================
"""OFFLINE, non-invasive analysis of operator-provided network edge telemetry.

Input: normalized/Zeek JSONL flows, Zeek JSONL DNS, optional local IoC JSON.
Output: JSONL indicators + ML features, summary, SHA256SUMS. Never fetches feeds,
connects to a host, decrypts data, or claims that WPA beacons expose IP flows.
All alerts are hypotheses requiring corroboration, not botnet labels.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import statistics
import sys

SEAL = 'CJB-DEV-2026'
SCHEMA = 'bci.orbital.flow-intel.v1'
MAX_ROWS = 200000
MAX_BYTES = 100 * 1024 * 1024


def timestamp(value):
    try:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value.replace('.', '', 1).isdigit():
            return float(value)
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f'invalid timestamp {str(value)[:60]}')


def as_int(value, default=0):
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError, OverflowError):
        return default


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return ''


def normalize_domain(value):
    return str(value or '').lower().rstrip('.').strip()[:253]


def load_jsonl(path, kind):
    if not path:
        return []
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError(f'{kind} file absent or larger than {MAX_BYTES} bytes')
    data = []
    with p.open(encoding='utf-8') as stream:
        for n, line in enumerate(stream, 1):
            if n > MAX_ROWS:
                raise ValueError(f'{kind} exceeds {MAX_ROWS} rows')
            if not line.strip() or line.startswith('#'):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{kind} line {n}: {exc}') from exc
            if not isinstance(entry, dict):
                raise ValueError(f'{kind} line {n}: expected object')
            try:
                if kind == 'flow':
                    src = valid_ip(entry.get('src_ip') or entry.get('id.orig_h'))
                    dst = valid_ip(entry.get('dst_ip') or entry.get('id.resp_h'))
                    if not src or not dst:
                        continue
                    data.append({'ts': timestamp(entry.get('ts', entry.get('timestamp'))),
                                 'src': src, 'dst': dst,
                                 'port': as_int(entry.get('dst_port', entry.get('id.resp_p'))),
                                 'src_port': as_int(entry.get('src_port', entry.get('id.orig_p'))),
                                 'proto': str(entry.get('proto', '')).lower(),
                                 'bytes': as_int(entry.get('bytes',
                                     as_int(entry.get('orig_bytes')) + as_int(entry.get('resp_bytes')))),
                                 'service': str(entry.get('service') or entry.get('app_protocol') or '').lower(),
                                 'tcp_flags': str(entry.get('tcp_flags', '')).upper(),
                                 'http_method': str(entry.get('http_method') or entry.get('method') or '').upper(),
                                 'domain': normalize_domain(entry.get('domain') or entry.get('host')),
                                 'dst_asn': str(entry.get('dst_asn') or '')})
                else:
                    src = valid_ip(entry.get('src_ip') or entry.get('id.orig_h'))
                    if not src:
                        continue
                    answers = entry.get('answers') or []
                    if isinstance(answers, str):
                        answers = [answers]
                    data.append({'ts': timestamp(entry.get('ts', entry.get('timestamp'))),
                                 'src': src, 'domain': normalize_domain(entry.get('query') or entry.get('domain')),
                                 'rcode': str(entry.get('rcode_name') or entry.get('rcode') or '').upper(),
                                 'answers': [valid_ip(x) for x in answers if valid_ip(x)]})
            except ValueError as exc:
                raise ValueError(f'{kind} line {n}: {exc}') from exc
    return sorted(data, key=lambda x: x['ts'])


def load_ioc(path):
    if not path:
        return {'ips': set(), 'domains': set(), 'asns': set(), 'new_domains': set(), 'ddns_suffixes': set()}
    p = Path(path)
    if not p.is_file() or p.stat().st_size > 5 * 1024 * 1024:
        raise ValueError('IOC file unavailable or too large')
    obj = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('IOC JSON must be an object')
    return {'ips': {valid_ip(x) for x in obj.get('ips', []) if valid_ip(x)},
            'domains': {normalize_domain(x) for x in obj.get('domains', [])},
            'asns': {str(x).upper().removeprefix('AS') for x in obj.get('asns', [])},
            'new_domains': {normalize_domain(x) for x in obj.get('new_domains', [])},
            'ddns_suffixes': {normalize_domain(x) for x in obj.get('ddns_suffixes', [])}}


def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in counts.values())


def domain_matches(domain, entries):
    return any(domain == x or domain.endswith('.' + x) for x in entries if x)


def analyze(flows, dns, ioc):
    """Return event hypotheses and aggregate features; no attack attribution."""
    events = []
    def flag(kind, src, detail, count, evidence, confidence='low'):
        events.append({'type': kind, 'src': src, 'detail': detail,
                       'observations': int(count), 'evidence_source': evidence,
                       'confidence': confidence, 'label': None,
                       'assessment': 'anomaly_requires_correlating_evidence'})

    # Periodic callback-like flow bursts: distinct connections, not Wi-Fi beacons.
    by_path = defaultdict(list)
    by_src = defaultdict(list)
    for flow in flows:
        by_path[(flow['src'], flow['dst'], flow['port'], flow['proto'])].append(flow['ts'])
        by_src[flow['src']].append(flow)
    for (src, _, port, proto), times in by_path.items():
        if len(times) < 6:
            continue
        gaps = [b-a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < 5:
            continue
        med = statistics.median(gaps)
        if 10 <= med <= 3600 and statistics.pstdev(gaps)/max(statistics.mean(gaps), 1) <= 0.15:
            flag('periodic_external_flow', src, f'connections to same endpoint/{proto}/{port} at ~{med:.0f}s intervals',
                 len(times), 'edge_flow', 'medium')

    for src, fs in by_src.items():
        # SMTP broad delivery pattern.
        smtp = {f['dst'] for f in fs if f['port'] in (25, 465, 587)}
        if len(smtp) >= 15:
            flag('smtp_fanout', src, f'SMTP traffic to {len(smtp)} destinations', len(smtp), 'edge_flow')
        # Many remote targets or ports in <=5m windows; coarse per-source scan heuristic.
        start = 0
        while start < len(fs):
            end = start
            while end < len(fs) and fs[end]['ts'] < fs[start]['ts'] + 300:
                end += 1
            subset = fs[start:end]
            if len(subset) >= 25:
                unique_dsts = {f['dst'] for f in subset}
                target_ports = {f['port'] for f in subset}
                if len(unique_dsts) >= 25 or len(target_ports) >= 30:
                    flag('external_target_fanout', src,
                         f'{len(unique_dsts)} distinct destinations, {len(target_ports)} ports within 5 minutes',
                         len(subset), 'edge_flow')
                    break
            start = max(end, start + 1)
        if any(f['service'] in ('http','ssl','tls','https') and f['port'] == 53 for f in fs):
            flag('protocol_port_mismatch', src, 'HTTP/TLS service labelled on DNS port 53',
                 sum(f['service'] in ('http','ssl','tls','https') and f['port'] == 53 for f in fs),
                 'edge_flow')
        gets = [f for f in fs if f['http_method'] == 'GET']
        if len(gets) >= 100:
            first = gets[0]['ts']
            count = sum(f['ts'] < first+60 for f in gets)
            if count >= 100:
                flag('high_rate_http_get', src, f'{count} HTTP GET flow records in one minute',
                     count, 'edge_flow')
        icmp = [f for f in fs if f['proto'] == 'icmp' and f['bytes'] >= 1000]
        if len(icmp) >= 10:
            flag('large_icmp_flows', src, 'repeated unusually large ICMP flow summaries', len(icmp), 'edge_flow')

    # Aggregate outbound UDP spikes, if provided flow bytes contain sufficient evidence.
    udp_by_target = defaultdict(list)
    for f in flows:
        if f['proto'] == 'udp':
            udp_by_target[f['dst']].append(f)
    for dest, rows in udp_by_target.items():
        start = 0
        while start < len(rows):
            end = start
            while end < len(rows) and rows[end]['ts'] < rows[start]['ts'] + 60:
                end += 1
            subset = rows[start:end]
            size = sum(f['bytes'] for f in subset)
            if len(subset) >= 100 and size >= 5_000_000:
                flag('outbound_udp_volume_spike', '|'.join(sorted({f['src'] for f in subset})[:5]),
                     f'{len(subset)} UDP flows and {size} bytes toward one destination in 60 seconds',
                     len(subset), 'edge_flow')
                break
            start = max(end, start+1)
    # Outbound SYN fan-in toward one destination; independent timestamp windows.
    syn_by_dst = defaultdict(list)
    for f in flows:
        if f['proto'] == 'tcp' and 'S' in f['tcp_flags'] and 'A' not in f['tcp_flags']:
            syn_by_dst[f['dst']].append(f)
    for dst, fs in syn_by_dst.items():
        start = 0
        while start < len(fs):
            end = start
            while end < len(fs) and fs[end]['ts'] < fs[start]['ts'] + 60:
                end += 1
            burst = fs[start:end]
            if len(burst) >= 100:
                srcs = {f['src'] for f in burst}
                flag('possible_syn_flood', '|'.join(sorted(srcs)[:5]),
                     f'{len(burst)} outbound SYN-flow summaries to one target in 60 seconds from {len(srcs)} sources',
                     len(burst), 'edge_flow')
                break
            start = max(end, start+1)

    dns_by_src = defaultdict(list)
    answer_by_domain = defaultdict(set)
    clients_by_domain = defaultdict(set)
    for d in dns:
        dns_by_src[d['src']].append(d)
        if d['domain']:
            clients_by_domain[d['domain']].add(d['src'])
            answer_by_domain[d['domain']].update(d['answers'])
    for src, rows in dns_by_src.items():
        failed = [d for d in rows if d['rcode'] in ('NXDOMAIN', '3')]
        random_lookups = {d['domain'] for d in failed
            if len(d['domain'].split('.')[0]) >= 12 and entropy(d['domain'].split('.')[0]) >= 3.3}
        if len(failed) >= 15 and len(random_lookups) >= 10:
            flag('dga_like_nxdomain', src,
                 f'{len(failed)} NXDOMAIN replies; {len(random_lookups)} high-entropy unique names',
                 len(failed), 'dns_log', 'medium')

    # Correlation against an explicitly supplied local IoC list, no network calls.
    for src, fs in by_src.items():
        matched = sum(f['dst'] in ioc['ips'] or
                      (f['domain'] and domain_matches(f['domain'], ioc['domains'])) or
                      (f['dst_asn'].upper().removeprefix('AS') in ioc['asns'] and bool(f['dst_asn']))
                      for f in fs)
        if matched:
            flag('local_ioc_match', src, 'flow destination matched supplied IP/domain/ASN list',
                 matched, 'local_ioc_and_edge_flow', 'medium')
    for src, rows in dns_by_src.items():
        count = sum(domain_matches(d['domain'], ioc['domains']) for d in rows)
        if count:
            flag('local_dns_ioc_match', src, 'DNS query matched supplied domain list',
                 count, 'local_ioc_and_dns_log', 'medium')
    for domain, srcs in clients_by_domain.items():
        if len(srcs) < 3:
            continue
        if (domain_matches(domain, ioc['ddns_suffixes']) or
            domain_matches(domain, ioc['new_domains']) or
            domain_matches(domain, ioc['domains'])):
            flag('shared_suspicious_domain', '|'.join(sorted(srcs)[:5]),
                 f'{len(srcs)} sources queried a domain on supplied DDNS/new/reputation list',
                 len(srcs), 'dns_log_and_local_ioc')
        if len(answer_by_domain[domain]) >= 6:
            flag('multiple_dns_answers', '|'.join(sorted(srcs)[:5]),
                 f'{len(answer_by_domain[domain])} distinct observed DNS addresses for one domain',
                 len(answer_by_domain[domain]), 'dns_log')
    summary = {'flow_rows': len(flows), 'dns_rows': len(dns),
               'sources': len(set(by_src) | set(dns_by_src)),
               'events': len(events),
               'event_types': dict(Counter(e['type'] for e in events)),
               'telemetry_scope': 'provided_edge_flow_and_dns_only; not_from_wifi_beacons'}
    return events, summary


def write_outputs(events, summary, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(24)
    def anon(x):
        return hashlib.sha256(salt + x.encode('utf-8')).hexdigest()[:20]
    path = dest/'flow_indicators.jsonl'
    with path.open('w', encoding='utf-8') as out:
        for e in events:
            sanitized = dict(e)
            sanitized['src_id'] = anon(sanitized.pop('src'))
            sanitized.update(schema_version=SCHEMA, developer_seal=SEAL,
                             synthetic=False)
            out.write(json.dumps(sanitized, sort_keys=True) + '\n')
    summary = {**summary, 'schema_version': SCHEMA,
               'developer_seal': SEAL, 'ground_truth_botnet_labels': False}
    (dest/'flow_summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    with (dest/'flow_ml_features.jsonl').open('w', encoding='utf-8') as out:
        for e in events:
            feat = {'schema_version': SCHEMA, 'record_type': 'unverified_flow_indicator',
                    'source_id': anon(e['src']), 'features': {
                        'indicator_type': e['type'], 'observations': e['observations'],
                        'confidence': e['confidence'], 'source_type': e['evidence_source']},
                    'label': None, 'synthetic': False, 'developer_seal': SEAL}
            out.write(json.dumps(feat, sort_keys=True) + '\n')
    entries = []
    for filename in ('flow_summary.json', 'flow_indicators.jsonl', 'flow_ml_features.jsonl'):
        entries.append(f'{hashlib.sha256((dest/filename).read_bytes()).hexdigest()}  {filename}')
    (dest/'SHA256SUMS').write_text('\n'.join(entries)+'\n', encoding='utf-8')
    return dest


def main(argv=None):
    ap = argparse.ArgumentParser(description='BCI Orbital Sentinel offline edge flow and DNS heuristic analyzer')
    ap.add_argument('--flows', help='normalized or Zeek JSONL conn records')
    ap.add_argument('--dns', help='Zeek JSONL DNS records')
    ap.add_argument('--ioc', help='local JSON with ips/domains/asns/new_domains/ddns_suffixes arrays')
    ap.add_argument('--out-dir', required=True)
    args = ap.parse_args(argv)
    if not args.flows and not args.dns:
        ap.error('provide at least --flows or --dns')
    try:
        flows = load_jsonl(args.flows, 'flow')
        dns = load_jsonl(args.dns, 'dns')
        indicators, summary = analyze(flows, dns, load_ioc(args.ioc))
        result = write_outputs(indicators, summary, args.out_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'[BCI][ERROR] Flow analysis: {exc}', file=sys.stderr)
        return 1
    print(f'[BCI] {len(flows)} flows, {len(dns)} DNS queries, {len(indicators)} unverified indicators')
    print(f'[BCI] Reports: {result}; SHA256SUMS created')
    return 0


if __name__ == '__main__':
    sys.exit(main())
