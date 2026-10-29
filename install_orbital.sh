#!/usr/bin/env bash
# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL SENTINEL INSTALLER v4.6.13-NETSCOPE
# Developer Seal: CJB-DEV-2026
# Project Seal: BEACON-COMPUTING-INITIATIVE-ORBITAL-SENTINEL-LINUX
# SHA-256: recorded in release SHA256SUMS
# ============================================================================
# This installer is safe to paste/run from a normal user terminal. It never
# changes interface modes, kills NetworkManager, or exits the invoking shell.
set -euo pipefail
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEST="${BCI_ORBITAL_HOME:-$HOME/BCI/Docker Projects/orbital}"
FILES=(install_orbital.sh release_manifest.json Dockerfile compose.yaml sentinel_exporter.py sentinel_gui.py \
    bci_monitor_select.py flow_intel.py network_scope.py orbitalctl.sh start_sentinel_gui.sh bci-sentinel-gui.service \
    .github/workflows/ci.yml .gitignore CONTRIBUTING.md assets/cerberus-bci.jpg)

if [[ "${1:-}" == "--install-deps" ]]; then
    printf '[BCI] Installing required Kali/Ubuntu packages on explicit request.\n'
    sudo apt-get update
    sudo apt-get install -y python3 python3-pyqt6 tshark iw docker.io
    if ! docker compose version >/dev/null 2>&1 && ! sudo docker compose version >/dev/null 2>&1; then
        sudo apt-get install -y docker-compose-plugin || sudo apt-get install -y docker-compose
    fi
fi

printf '[BCI] Source: %s\n[BCI] Destination: %s\n' "$SOURCE" "$DEST"
# Install source files if and only if the release hash manifest passes.
(cd "$SOURCE" && sha256sum -c --quiet SHA256SUMS) || {
    echo '[BCI][ERROR] Source failed SHA-256 verification; no files installed.' >&2
    exit 1
}
python3 -m py_compile "$SOURCE/sentinel_exporter.py" "$SOURCE/sentinel_gui.py" "$SOURCE/bci_monitor_select.py" "$SOURCE/flow_intel.py" "$SOURCE/network_scope.py" || exit 1

if [[ -f "$DEST/orbitalctl.sh" ]]; then
    echo '[BCI] Existing project found. Stop existing capture with: bash "$HOME/BCI/Docker Projects/orbital/orbitalctl.sh" stop' >&2
    echo '[BCI] Installer will not stop a running capture without operator action.' >&2
    if command -v docker >/dev/null 2>&1 && \
       docker ps --format '{{.Names}}' 2>/dev/null | grep -Eq '^bci-orbital-sentinel-467-'; then
        echo '[BCI][ERROR] Existing capture running; stop first.' >&2; exit 1
    fi
fi
mkdir -p "$DEST" "$DEST/captures" "$HOME/.local/bin" "$HOME/.config/systemd/user"
if [[ "$SOURCE" != "$DEST" ]]; then
    # Back up only the files we are replacing. Never copy/delete captures.
    backup="$DEST/backups/$(date -u +%Y%m%dT%H%M%SZ)"
    for file in "${FILES[@]}"; do
        if [[ -e "$DEST/$file" ]]; then
            mkdir -p "$backup"
            mkdir -p "$backup/$(dirname -- "$file")"
            cp -p -- "$DEST/$file" "$backup/$file"
        fi
    done
    for file in "${FILES[@]}"; do
        install -D -m 0644 -- "$SOURCE/$file" "$DEST/$file"
    done
    chmod 0755 "$DEST/orbitalctl.sh" "$DEST/start_sentinel_gui.sh" "$DEST/sentinel_exporter.py" "$DEST/sentinel_gui.py" "$DEST/bci_monitor_select.py" "$DEST/flow_intel.py" "$DEST/network_scope.py"
    cp -- "$SOURCE/SHA256SUMS" "$DEST/SHA256SUMS"
    cp -- "$SOURCE/README.md" "$DEST/README.md"
    mkdir -p "$DEST/tests"
    cp -- "$SOURCE"/tests/test_*.py "$DEST/tests/"
else
    chmod 0755 "$DEST/orbitalctl.sh" "$DEST/start_sentinel_gui.sh"
fi

ln -sfn -- "$DEST/orbitalctl.sh" "$HOME/.local/bin/bci-orbital"
ln -sfn -- "$DEST/start_sentinel_gui.sh" "$HOME/.local/bin/bci-orbital-gui"
install -m 0644 "$SOURCE/bci-sentinel-gui.service" "$HOME/.config/systemd/user/bci-sentinel-gui.service"
if command -v systemctl >/dev/null && [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
    systemctl --user daemon-reload || printf '[BCI][WARN] User systemd unavailable; CLI/GUI remain usable.\n'
fi
printf '[BCI] Installed. No container or desktop service was started automatically.\n'
printf '[BCI] Run: "%s/orbitalctl.sh" doctor\n' "$DEST"
printf '[BCI] Then: "%s/orbitalctl.sh" start\n' "$DEST"
printf '[BCI] GUI: "%s/start_sentinel_gui.sh"\n' "$DEST"
printf '[BCI] Optional automatic GUI service: "%s/orbitalctl.sh" enable-gui\n' "$DEST"
