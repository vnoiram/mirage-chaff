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
# API mode needs AGH_KILLSWITCH_TARGETS set to the cushion rewrite answers to
# delete, separated by commas and/or whitespace. Examples:
#   AGH_KILLSWITCH_TARGETS="192.0.2.10 2001:db8::10"
#   AGH_KILLSWITCH_TARGETS="mirage-chaff.lan"
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

api_url() {
  printf '%s/%s\n' "${AGH_API_URL%/}" "$1"
}

delete_rewrites_via_api() {
  if [ -z "${AGH_KILLSWITCH_TARGETS:-}" ]; then
    log "API credentials found, but AGH_KILLSWITCH_TARGETS is unset; falling back to file method"
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    log "curl not found; falling back to file method"
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    log "jq not found; falling back to file method"
    return 1
  fi

  local list payloads count jq_targets
  if ! list="$(curl -fsS -u "${AGH_API_USER}:${AGH_API_PASS}" "$(api_url control/rewrite/list)")"; then
    log "failed to list AGH rewrites via API; falling back to file method"
    return 1
  fi
  jq_targets="$(printf '%s' "$AGH_KILLSWITCH_TARGETS" \
    | tr ' ,\t' '\n' | grep -v '^$' \
    | jq -Rsc 'split("\n") | map(select(. != ""))')"
  if ! payloads="$(printf '%s' "$list" | jq -rc \
    --argjson targets "$jq_targets" \
    '.[] | select(.answer as $a | $targets | index($a) != null) | {domain,answer}')"; then
    log "failed to parse AGH rewrite list; falling back to file method"
    return 1
  fi

  if [ -z "$payloads" ]; then
    log "no AGH rewrites matched AGH_KILLSWITCH_TARGETS; falling back to file method"
    return 1
  fi

  count=0
  while IFS= read -r payload; do
    [ -n "$payload" ] || continue
    if ! curl -fsS -u "${AGH_API_USER}:${AGH_API_PASS}" \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "$(api_url control/rewrite/delete)" >/dev/null; then
      log "failed to delete AGH rewrite via API; falling back to file method"
      return 1
    fi
    count=$((count + 1))
  done <<<"$payloads"
  log "deleted $count AGH rewrite(s) via API"
  return 0
}

# shellcheck disable=SC1090
[ -f "$AGH_ENV" ] && . "$AGH_ENV" || true

if [ -n "${AGH_API_URL:-}" ] && [ -n "${AGH_API_USER:-}" ] && [ -n "${AGH_API_PASS:-}" ]; then
  log "using AGH API at ${AGH_API_URL} (no restart)"
  if delete_rewrites_via_api; then
    log "curated domains now resolve normally"
    exit 0
  fi
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
