#!/usr/bin/env python3
# ============================================================================
# BEACON COMPUTING INITIATIVE | PASSIVE INTERFACE SELECTOR v4.6.15-IFACEGUI
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



def parse_link_inventory(output: str) -> list[dict]:
    """List local interfaces without requiring carrier, IP or internet service."""
    import json
    entries = json.loads(output)
    if not isinstance(entries, list):
        raise ValueError("Unexpected ip -j link response")
    result = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("ifname", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            continue
        result.append({
            "name": name,
            "up": "UP" in entry.get("flags", []),
            "link_type": entry.get("link_type", ""),
        })
    return result


def choose_any(links: list[dict], radios: list[dict], requested: str = "auto") -> tuple[str, str]:
    """Choose if and only if the named interface exists, or return idle on no device.

    Never change link state, Wi-Fi mode, routing, or NetworkManager settings.
    """
    types = {item["name"]: item["type"] for item in radios}
    records = {item["name"]: item for item in links}
    if requested in ("none", "idle", "offline"):
        return "none", "idle"
    if requested != "auto":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", requested):
            raise ValueError("Invalid interface name")
        if requested not in records:
            raise ValueError("Interface not present: " + requested)
        if requested == "lo":
            return "lo", "loopback"
        return requested, types.get(requested, "ethernet")

    excluded = ("veth", "docker", "br-", "virbr", "tailscale",
                "tun", "tap", "wg", "zt", "ifb")
    eligible = [x for x in links
                if x["name"] != "lo"
                and not x["name"].startswith(excluded)]
    if not eligible:
        return "none", "idle"
    # An UP interface is preferred, but DOWN interfaces remain eligible.
    def ordering(link: dict):
        name = link["name"]
        kind = types.get(name, "ethernet")
        preference = {"monitor": 0, "managed": 1, "ethernet": 2}.get(kind, 3)
        return (not link["up"], preference, name)

    selected = sorted(eligible, key=ordering)[0]
    return selected["name"], types.get(selected["name"], "ethernet")



def discover_interfaces() -> tuple[list[dict], list[dict]]:
    """Inspect every local interface, including DOWN/unconnected interfaces."""
    result = subprocess.run(["ip", "-j", "link", "show"], capture_output=True,
                            text=True, timeout=8, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "ip link failed")
    links = parse_link_inventory(result.stdout)
    radios: list[dict] = []
    try:
        wireless = subprocess.run(["iw", "dev"], capture_output=True,
                                  text=True, timeout=5, check=False)
        if wireless.returncode == 0:
            radios = parse_iw_inventory(wireless.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return links, radios


def interface_choices() -> list[dict]:
    """Return GUI choices without making a single network connection."""
    links, radios = discover_interfaces()
    radio_types = {item["name"]: item["type"] for item in radios}
    options = [
        {"name": "auto", "mode": "auto", "up": None,
         "label": "Auto — choose an existing local interface"},
        {"name": "none", "mode": "idle", "up": None,
         "label": "None — Idle / historical data only"},
    ]
    for device in links:
        name = device["name"]
        kind = ("loopback" if name == "lo"
                else radio_types.get(name, "ethernet"))
        state = "UP" if device["up"] else "DOWN / offline"
        options.append({
            "name": name, "mode": kind, "up": device["up"],
            "label": f"{name} — {kind} — {state}",
        })
    return options


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Select existing passive interface or idle mode (no online requirement)")
    parser.add_argument("--iface", default="auto")
    parser.add_argument("--format", choices=("name", "tab"), default="name")
    args = parser.parse_args()
    try:
        links, radios = discover_interfaces()
        interface, mode = choose_any(links, radios, args.iface)
        if args.format == "tab":
            print(interface + "\t" + mode)
        else:
            print(interface)
        print("[BCI] existing interface=" + interface + " mode=" + mode +
              " (no internet requirement; no interface changes)", file=sys.stderr)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print("[BCI][ERROR] " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
