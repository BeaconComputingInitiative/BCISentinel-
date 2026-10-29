#!/usr/bin/env bash
# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL CONTROL v4.6.11-TRACE
# Developer Seal: CJB-DEV-2026
# Project Seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX
# SHA-256: see SHA256SUMS
# ============================================================================
set -u
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
cd "$HERE" || exit 1
COMMAND="${1:-help}"
shift || true

say() { printf '[BCI] %s\n' "$*"; }
fail() { printf '[BCI][ERROR] %s\n' "$*" >&2; return 1; }

setup_docker() {
    if ! command -v docker >/dev/null; then fail 'Docker not found; see README dependency instructions'; return 1; fi
    if docker info >/dev/null 2>&1; then
        DOCKER=(docker)
    elif command -v sudo >/dev/null && sudo -n docker info >/dev/null 2>&1; then
        DOCKER=(sudo -n docker)
    else
        say 'Docker requires sudo on this host; you may be asked for your password.'
        DOCKER=(sudo docker)
    fi
    if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
        COMPOSE=("${DOCKER[@]}" compose)
    elif command -v docker-compose >/dev/null; then
        if [[ "${DOCKER[0]}" == sudo ]]; then COMPOSE=(sudo docker-compose)
        else COMPOSE=(docker-compose); fi
    else
        fail 'Docker Compose is unavailable; install docker-compose-plugin or docker-compose'; return 1
    fi
}

get_iface() {
    command -v iw >/dev/null || { fail 'iw is not installed'; return 1; }
    BCI_IFACE="$(python3 "$HERE/bci_monitor_select.py" --iface "${BCI_IFACE:-auto}")" || return 1
    export BCI_IFACE
    say "Selected existing monitor-mode interface: $BCI_IFACE"
}

verify_project() {
    [[ -f "$HERE/SHA256SUMS" ]] || { fail 'Missing SHA256SUMS'; return 1; }
    (cd "$HERE" && sha256sum -c --quiet SHA256SUMS) || { fail 'Release integrity verification failed'; return 1; }
}

verify_storage() {
    [[ -d "$HERE/captures" ]] || { fail 'captures directory missing'; return 1; }
    [[ -w "$HERE/captures" ]] || { fail 'captures is not writable by host user'; return 1; }
    # Test as the same container runtime and mount used for capture.
    "${COMPOSE[@]}" run --no-deps --rm --entrypoint python3 sentinel \
       -c 'import os,tempfile; f=tempfile.NamedTemporaryFile(dir="/data",delete=False);f.write(b"BCI storage PASS\n");f.close();os.unlink(f.name)' \
       >/dev/null || { fail 'Container cannot write /data; no capture started'; return 1; }
}

prepare_image() {
    local target='bci/orbital-sentinel:4.6.11-TRACE'
    if "${DOCKER[@]}" image inspect "$target" >/dev/null 2>&1; then
        say 'Using cached v4.6.11-TRACE image (no registry download)'; return 0
    fi
    # Reuse cached runtime if and only if the source image is present.
    # Compose overrides any inherited ENTRYPOINT with the repaired exporter.
    local existing
    for existing in \
      'bci/orbital-sentinel:4.6.10-C2HUNT' \
      'bci/orbital-sentinel:4.6.8-op2' \
      'bci/orbital-sentinel:4.6.7-op2' \
      'bci/orbital-sentinel:4.6.7-op1' \
      'bci/orbital-sentinel:4.6.2-auto-ml-jsonl'; do
        if "${DOCKER[@]}" image inspect "$existing" >/dev/null 2>&1; then
            say "Using cached runtime $existing with v4.6.11-TRACE source"
            "${DOCKER[@]}" tag "$existing" "$target" || return 1
            return 0
        fi
    done
    say 'No cached runtime found; attempting Docker build (requires registry access)'
    "${COMPOSE[@]}" build || { fail 'Build failed; check Docker Hub access and BCILock egress policy'; return 1; }
}

sync_vendor_database() {
    # Local-only, no network lookups; preserve an existing dataset if installed.
    local path
    for path in /usr/share/ieee-data/oui.txt /usr/share/wireshark/manuf /var/lib/ieee-data/oui.txt; do
        if [[ -s "$path" ]]; then
            cp -- "$path" "$HERE/captures/vendor_oui.txt" || return 1
            chmod a+r "$HERE/captures/vendor_oui.txt" || return 1
            say "Vendor OUI database available from $path"
            return 0
        fi
    done
    say 'No host OUI registry found; vendor fields will explicitly say unknown/randomized'
}

check_ports() {
    python3 - <<'PY'
import socket,sys
for port in (9100,9101):
    sk=socket.socket()
    try:
        sk.bind(('127.0.0.1',port))
    except OSError as e:
        print(f'[BCI][ERROR] TCP port {port} occupied: {e}',file=sys.stderr)
        sys.exit(1)
    finally:
        sk.close()
print('[BCI] Metrics ports 9100 and 9101 are available')
PY
}

case "$COMMAND" in
    doctor)
        say 'Orbital Sentinel v4.6.11-TRACE — diagnostic mode (read-only)'
        get_iface || exit 1
        if setup_docker; then
            "${DOCKER[@]}" image ls 'bci/orbital-sentinel' || true
            "${COMPOSE[@]}" ps -a || true
        fi
        ;;
    verify)
        verify_project && say 'SHA-256 PASS'
        ;;
    test)
        verify_project || exit 1
        python3 -m unittest discover -s tests -v
        ;;
    build)
        verify_project && setup_docker && "${COMPOSE[@]}" build
        ;;
    start)
        # Capture starts if and only if integrity, monitor-radio, Docker,
        # port-availability, and container-storage gates all pass.
        verify_project || exit 1
        get_iface || exit 1
        setup_docker || exit 1
        if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -q .; then
            fail 'An Orbital service is already running; run status before restarting'; exit 1
        fi
        check_ports || exit 1
        prepare_image || exit 1
        verify_storage || exit 1
        sync_vendor_database || exit 1
        say 'Launching both original passive capture services (sentinel, discovery)'
        "${COMPOSE[@]}" up --detach --no-build || exit 1
        sleep 2
        "${COMPOSE[@]}" ps -a
        "${COMPOSE[@]}" ps --status running --services | grep -qx sentinel || { fail 'Sentinel service did not stay running'; "${COMPOSE[@]}" logs --tail 60 sentinel; exit 1; }
        "${COMPOSE[@]}" ps --status running --services | grep -qx discovery || { fail 'Discovery service did not stay running'; "${COMPOSE[@]}" logs --tail 60 discovery; exit 1; }
        say "Startup PASS (processes running); check logs and metrics for actual packet reception"
        ;;
    stop)
        setup_docker && "${COMPOSE[@]}" stop
        ;;
    status)
        setup_docker && "${COMPOSE[@]}" ps -a
        ;;
    logs)
        setup_docker && "${COMPOSE[@]}" logs --tail 100 "$@"
        ;;
    gui)
        exec "$HERE/start_sentinel_gui.sh"
        ;;
    enable-gui)
        systemctl --user daemon-reload && systemctl --user enable bci-sentinel-gui.service && say 'GUI enabled; use bci-orbital gui for immediate launch'
        ;;
    disable-gui)
        systemctl --user disable --now bci-sentinel-gui.service
        ;;
    flow-analyze)
        # Separate optional analysis of supplied edge telemetry; no RF attribution.
        python3 "$HERE/flow_intel.py" "$@"
        ;;
    hunt-c2)
        python3 - <<'PYHUNT'
import json,urllib.request,sys
try:
    with urllib.request.urlopen('http://127.0.0.1:9100/hunt_c2',timeout=8) as response:
        result=json.load(response)
    print(json.dumps(result,indent=2,ensure_ascii=False))
    sys.exit(0 if result.get('success') else 1)
except Exception as exc:
    print(f'[BCI][ERROR] C2 hunt API unavailable: {exc}',file=sys.stderr)
    sys.exit(1)
PYHUNT
        ;;
    trace)
        # Passive AP report. Optionally: trace BSSID
        TRACE_BSSID="${1:-}"
        TRACE_BSSID="$TRACE_BSSID" python3 - <<'PYTRACE'
import os,json,sys,urllib.request,urllib.parse
bssid=os.getenv('TRACE_BSSID','')
url='http://127.0.0.1:9100/trace'
if bssid: url+='?'+urllib.parse.urlencode({'bssid':bssid})
try:
    with urllib.request.urlopen(url,timeout=8) as resp: obj=json.load(resp)
    print(json.dumps(obj,indent=2,ensure_ascii=False))
    sys.exit(0 if obj.get('success') else 1)
except Exception as exc:
    print(f'[BCI][ERROR] Auto-Trace unavailable: {exc}',file=sys.stderr)
    sys.exit(1)
PYTRACE
        ;;
    trace-probe)
        # Explicit operator action only; requires BCI_ACTIVE_PROBE_ENABLED=1
        # set at service startup and BSSID --authorize on the command line.
        TRACE_BSSID="${1:-}"
        if [[ "${2:-}" != '--authorize' || -z "$TRACE_BSSID" ]]; then
            fail 'Usage: orbitalctl.sh trace-probe BSSID --authorize'; exit 1
        fi
        TRACE_BSSID="$TRACE_BSSID" python3 - <<'PYPROBE'
import os,json,sys,urllib.request
body=json.dumps({'bssid':os.getenv('TRACE_BSSID',''),'authorized':True}).encode()
req=urllib.request.Request('http://127.0.0.1:9100/trace/probe',data=body,
                           headers={'Content-Type':'application/json'},method='POST')
try:
    with urllib.request.urlopen(req,timeout=8) as resp: obj=json.load(resp)
    print(json.dumps(obj,indent=2,ensure_ascii=False))
    sys.exit(0 if obj.get('success') else 1)
except Exception as exc:
    print(f'[BCI][ERROR] Explicit probe unavailable: {exc}',file=sys.stderr)
    sys.exit(1)
PYPROBE
        ;;
    metrics)
        python3 - <<'PY'
import urllib.request
for port in (9100,9101):
    print(f'===== 127.0.0.1:{port}/metrics =====')
    try:
        print(urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics',timeout=2).read().decode())
    except Exception as exc:
        print(f'[BCI][ERROR] {exc}')
PY
        ;;
    *)
        cat <<'USAGE'
[BCI] Orbital Sentinel controls:
  bci-orbital doctor        Read-only interface and Docker check
  bci-orbital verify        Verify release file SHA-256 hashes
  bci-orbital test          Run regression suite
  bci-orbital start         Start both original capture services
  bci-orbital status        Show container state
  bci-orbital logs          Read container logs
  bci-orbital metrics       Read local Prometheus metrics
  bci-orbital hunt-c2       Review wireless indicators and imported edge telemetry
  bci-orbital trace [BSSID] Passive AP trace with station evidence, JSONL audit
  bci-orbital trace-probe BSSID --authorize  Optional bounded directed probes (explicit opt-in only)
  bci-orbital flow-analyze --flows F.jsonl --dns D.jsonl --ioc I.json --out-dir DIR
  bci-orbital gui           Launch PyQt6 GUI (desktop only)
  bci-orbital stop          Gracefully stop containers
  bci-orbital build         Build an image if Docker Hub works
  bci-orbital enable-gui    Enable optional GUI user service
  bci-orbital disable-gui   Disable GUI user service
Set BCI_IFACE=<monitor-device> to select explicitly if more than one exists.
USAGE
        ;;
esac
