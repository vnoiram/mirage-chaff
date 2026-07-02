#!/usr/bin/env bash
# kill-switch.sh — emergency revert to the pre-mirage-chaff state (design doc A-4).
#
# Removes every AdGuard Home DNS rewrite that points curated domains at this
# cushion, so those domains resolve normally again while mirage-chaff is broken
# or being debugged. This is a CORE failsafe and does NOT depend on the optional
# AGH API: the default path edits AdGuardHome.yaml directly.
#
#   - If AGH API creds are present (agh.env: AGH_API_URL/AGH_API_USER/AGH_API_PASS),
#     prefer the API (no restart needed).
#   - Otherwise, strip the marker-delimited cushion block from AdGuardHome.yaml
#     (a timestamped backup is kept) and restart AdGuard Home.
#
# The cushion-managed rewrites in AdGuardHome.yaml must be wrapped in markers:
#   # >>> mirage-chaff managed rewrites >>>
#   ... rewrite entries ...
#   # <<< mirage-chaff managed rewrites <<<
set -euo pipefail

AGH_ENV="${AGH_ENV:-/etc/mirage-chaff/agh.env}"
AGH_YAML="${AGH_YAML:-/opt/AdGuardHome/AdGuardHome.yaml}"
AGH_SERVICE="${AGH_SERVICE:-AdGuardHome}"
BEGIN="# >>> mirage-chaff managed rewrites >>>"
END="# <<< mirage-chaff managed rewrites <<<"

log() { printf '[kill-switch] %s\n' "$*"; }

# shellcheck disable=SC1090
[ -f "$AGH_ENV" ] && . "$AGH_ENV" || true

if [ -n "${AGH_API_URL:-}" ] && [ -n "${AGH_API_USER:-}" ] && [ -n "${AGH_API_PASS:-}" ]; then
  log "using AGH API at ${AGH_API_URL} (no restart)"
  # TODO(Phase 5): enumerate /control/rewrite/list and delete cushion entries via
  # /control/rewrite/delete. Placeholder to keep the API path explicit.
  log "API path not yet implemented; falling back to file method"
fi

[ -f "$AGH_YAML" ] || { echo "AGH config not found: $AGH_YAML (set AGH_YAML)" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root to edit $AGH_YAML" >&2; exit 1; }

if ! grep -qF "$BEGIN" "$AGH_YAML"; then
  log "no mirage-chaff marker block found in $AGH_YAML; nothing to revert"
  exit 0
fi

BACKUP="${AGH_YAML}.bak.$(date +%Y%m%d-%H%M%S)"
cp -a "$AGH_YAML" "$BACKUP"
log "backed up -> $BACKUP"

# Delete everything between the markers (inclusive).
sed -i "/$(printf '%s' "$BEGIN" | sed 's/[.[\*^$/]/\\&/g')/,/$(printf '%s' "$END" | sed 's/[.[\*^$/]/\\&/g')/d" "$AGH_YAML"
log "removed cushion rewrite block from $AGH_YAML"

systemctl restart "$AGH_SERVICE"
log "restarted $AGH_SERVICE — curated domains now resolve normally"
