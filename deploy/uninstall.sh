#!/usr/bin/env bash
# uninstall.sh — remove mirage-chaff. Config/state are preserved unless --purge.
set -euo pipefail

NAME=mirage-chaff
PREFIX=/usr/local/bin
ETC=/etc/${NAME}
LIB=/var/lib/${NAME}
LOG=/var/log/${NAME}
UNIT=/etc/systemd/system/${NAME}.service
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
log() { printf '[uninstall] %s\n' "$*"; }

if systemctl list-unit-files | grep -q "^${NAME}.service"; then
  systemctl disable --now "${NAME}.service" || true
fi
rm -f "$UNIT"
systemctl daemon-reload || true
rm -f "${PREFIX}/${NAME}"
log "removed binary + unit"

if [ "$PURGE" -eq 1 ]; then
  log "PURGE: removing config, state (incl. CA keys!), logs, and user"
  rm -rf "$ETC" "$LIB" "$LOG"
  id -u "$NAME" >/dev/null 2>&1 && userdel "$NAME" || true
else
  log "kept $ETC, $LIB, $LOG (use --purge to remove; this deletes CA keys)"
fi
log "done"
