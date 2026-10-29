#!/usr/bin/env python3
# BEACON COMPUTING INITIATIVE | NETWORK SCOPE v4.6.13-NETSCOPE
# Developer Seal: CJB-DEV-2026
"""Pure presentation filters; does not alter the radio channel or capture service.

An unconfirmed station has no AP attribution. Imported edge-flow records are
not attributed to observed BSSIDs without explicit corroborating telemetry.
"""

def normalize_bssid(value):
    return str(value or '').strip().upper()


def visible_aps(aps, selected_bssid=None):
    if not selected_bssid:
        return list(aps)
    key = normalize_bssid(selected_bssid)
    return [ap for ap in aps if normalize_bssid(ap.get('bssid')) == key]


def visible_stations(stations, selected_bssid=None):
    if not selected_bssid:
        return list(stations)
    key = normalize_bssid(selected_bssid)
    return [st for st in stations
            if normalize_bssid(st.get('ap')) == key and
            st.get('association_evidence') not in ('unconfirmed', None, '')]


def visible_indicators(indicators, selected_bssid=None):
    if not selected_bssid:
        return list(indicators)
    key = normalize_bssid(selected_bssid)
    return [event for event in indicators if normalize_bssid(event.get('bssid')) == key]


def visible_dns(dns_per_ap, selected_bssid=None):
    if not selected_bssid:
        return dict(dns_per_ap)
    key = normalize_bssid(selected_bssid)
    return {k:v for k,v in dns_per_ap.items() if normalize_bssid(k)==key}


def scoped_ap_label(aps, selected_bssid):
    if not selected_bssid:
        return 'All observed networks (global capture)'
    match = visible_aps(aps, selected_bssid)
    return f"{match[0].get('ssid','<Hidden SSID>')} | {selected_bssid}" if match else f'{selected_bssid} (not currently observed)'
