#!/usr/bin/env bash
# ============================================================================
# BEACON COMPUTING INITIATIVE | ORBITAL GUI STARTER v4.6.7-op2
# Developer Seal: CJB-DEV-2026
# SHA-256: see SHA256SUMS
# ============================================================================
set -u
SOURCE="$(readlink -f -- "${BASH_SOURCE[0]}")" || exit 1
DIR="$(cd -- "$(dirname -- "$SOURCE")" && pwd -P)" || exit 1
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    printf '[BCI][ERROR] No graphical session. Open a Kali desktop terminal.\n' >&2
    exit 2
fi
if [[ ! -f "$DIR/sentinel_gui.py" ]]; then
    printf '[BCI][ERROR] GUI source missing: %s\n' "$DIR/sentinel_gui.py" >&2
    exit 3
fi
exec /usr/bin/python3 "$DIR/sentinel_gui.py"
