#!/usr/bin/env bash
# install.sh — idempotent installer for mirage-chaff (Linux + systemd).
#
# Safe to re-run: never overwrites existing config/policy/catalog, only fills in
# what is missing. Run as root.
set -euo pipefail

NAME=mirage-chaff
BIN_SRC="${BIN_SRC:-}"                       # optional prebuilt binary; else `go build`
PREFIX=/usr/local/bin
ETC=/etc/${NAME}
LIB=/var/lib/${NAME}
LOG=/var/log/${NAME}
UNIT=/etc/systemd/system/${NAME}.service
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }; }
log() { printf '[install] %s\n' "$*"; }

need_root

# 1. Binary: use prebuilt if given, else build from source.
if [ -n "$BIN_SRC" ]; then
  install -m 0755 "$BIN_SRC" "${PREFIX}/${NAME}"
else
  command -v go >/dev/null || { echo "go toolchain not found and BIN_SRC unset" >&2; exit 1; }
  log "building ${NAME} from source"
  ( cd "$REPO_DIR" && go build -trimpath -ldflags "-s -w" -o "${PREFIX}/${NAME}" ./cmd/${NAME} )
fi
log "installed binary -> ${PREFIX}/${NAME}"

# 2. Dedicated system user (least privilege).
if ! id -u "$NAME" >/dev/null 2>&1; then
  useradd --system --home-dir "$LIB" --shell /usr/sbin/nologin "$NAME"
  log "created system user ${NAME}"
fi

# 3. Directories + permissions. CA key dir and state are owner-only.
install -d -o "$NAME" -g "$NAME" -m 0755 "$ETC" "$ETC/policy.d" "$ETC/catalog"
install -d -o "$NAME" -g "$NAME" -m 0700 "$ETC/ca"
install -d -o "$NAME" -g "$NAME" -m 0700 "$LIB" "$LIB/certcache" "$LIB/admin"
install -d -o "$NAME" -g "$NAME" -m 0750 "$LOG"

# 4. Sample config/policy/catalog — install only if missing (idempotent).
copy_if_absent() { # src dst mode
  if [ ! -e "$2" ]; then install -o "$NAME" -g "$NAME" -m "$3" "$1" "$2"; log "placed $2"; else log "kept existing $2"; fi
}
copy_if_absent "$REPO_DIR/configs/mirage-chaff.conf.sample" "$ETC/mirage-chaff.conf" 0640
copy_if_absent "$REPO_DIR/configs/policy.d/example.yaml"     "$ETC/policy.d/example.yaml" 0640
for f in "$REPO_DIR"/configs/catalog/*; do
  copy_if_absent "$f" "$ETC/catalog/$(basename "$f")" 0640
done

# 5. Validate before enabling so a bad config never starts.
"${PREFIX}/${NAME}" check -config "$ETC/mirage-chaff.conf"

# 6. Initial admin bootstrap (only when admin is enabled and no users exist).
#    TODO(Phase 6): generate a temporary admin password, print it to the journal,
#    and force change on first login. Placeholder here in Phase 0.

# 7. systemd unit.
install -m 0644 "$REPO_DIR/deploy/${NAME}.service" "$UNIT"
systemctl daemon-reload
systemctl enable "${NAME}.service"
log "installed + enabled ${NAME}.service"

cat <<EOF
[install] done.

Next steps:
  1. Set up the intermediate CA (with Name Constraints):  deploy/gen-ca.sh
  2. Trust the root CA on your clients.
  3. Add AdGuard Home A/AAAA rewrites for curated domains -> this host's IP.
     (Bring ${NAME} up BEFORE adding rewrites, or those domains break.)
  4. If protocols.quic=false, block UDP/443:              deploy/firewall-udp443.sh
  5. Start:  systemctl start ${NAME}   &&   systemctl status ${NAME}
EOF
