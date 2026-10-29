#!/usr/bin/env python3
# ============================================================================
# BEACON COMPUTING INITIATIVE | MONITOR INTERFACE SELECTOR v4.6.7-op2
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
# ============================================================================
import argparse
import re
import subprocess
import sys


def parse_iw_inventory(output: str) -> list[dict]:
    interfaces: list[dict] = []
    phy = None
    current = None
    for line in output.splitlines():
        match = re.match(r'^phy#(\d+)\s*$', line.strip())
        if match:
            phy = match.group(1)
            current = None
            continue
        match = re.match(r'^\s*Interface\s+(\S+)\s*$', line)
        if match:
            current = {'name': match.group(1), 'phy': phy, 'type': 'unknown'}
            interfaces.append(current)
            continue
        match = re.match(r'^\s*type\s+(\S+)\s*$', line)
        if match and current is not None:
            current['type'] = match.group(1)
    return interfaces


def choose_monitor(devices: list[dict], requested: str = 'auto') -> str:
    monitors = [d for d in devices if d['type'] == 'monitor']
    if requested != 'auto':
        selected = [d for d in monitors if d['name'] == requested]
        if not selected:
            raise ValueError(f'{requested}: not listed as a monitor-mode interface')
    else:
        selected = monitors
    managed_phys = {d['phy'] for d in devices if d['type'] in ('managed', 'AP') and d['phy'] is not None}
    selected = [d for d in selected if d['phy'] is not None and d['phy'] not in managed_phys]
    if not selected:
        raise ValueError('No dedicated monitor-mode interface found; did not change any adapter')
    if len(selected) != 1:
        raise ValueError('Multiple dedicated monitor interfaces found: ' + ', '.join(d['name'] for d in selected) + '; set BCI_IFACE explicitly')
    return selected[0]['name']


def main() -> int:
    parser = argparse.ArgumentParser(description='Select existing dedicated monitor-mode wireless interface')
    parser.add_argument('--iface', default='auto')
    args = parser.parse_args()
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or 'iw dev failed')
        devices = parse_iw_inventory(result.stdout)
        for dev in devices:
            print(f"[BCI] seen {dev['name']} phy#{dev['phy']} type={dev['type']}", file=sys.stderr)
        print(choose_monitor(devices, args.iface))
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'[BCI][ERROR] {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
