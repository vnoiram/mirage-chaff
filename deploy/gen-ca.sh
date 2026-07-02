#!/usr/bin/env bash
# gen-ca.sh — generate a local root + a NAME-CONSTRAINED intermediate CA for
# mirage-chaff (design doc B-1). Future: replace with step-ca issuance (the
# daemon's leaf-issuance logic is unchanged).
#
# The intermediate is constrained (permitted DNS subtrees) so that even if the
# cushion / intermediate key is compromised, it can only mint leaves for the
# curated domains — not arbitrary sites like your bank. Curated set changes
# require re-issuing the intermediate (rotation).
#
# Usage:
#   deploy/gen-ca.sh -d .doubleclick.net -d .googlesyndication.com -d .google-analytics.com
#
# Outputs (default ./ca): root.crt, root.key, intermediate.crt, intermediate.key
set -euo pipefail

OUT="${OUT:-./ca}"
KEY_TYPE="${KEY_TYPE:-ecdsa}"   # ecdsa | rsa
DAYS_ROOT="${DAYS_ROOT:-3650}"
DAYS_INT="${DAYS_INT:-1825}"
DOMAINS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain) DOMAINS+=("$2"); shift 2 ;;
    -o|--out) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ "${#DOMAINS[@]}" -gt 0 ] || { echo "at least one -d <domain-suffix> is required (Name Constraints)" >&2; exit 2; }

mkdir -p "$OUT"; chmod 700 "$OUT"

genkey() { # outfile
  if [ "$KEY_TYPE" = "rsa" ]; then
    openssl genrsa -out "$1" 3072
  else
    openssl ecparam -name prime256v1 -genkey -noout -out "$1"
  fi
  chmod 600 "$1"
}

# --- Root CA ---
genkey "$OUT/root.key"
openssl req -x509 -new -key "$OUT/root.key" -sha256 -days "$DAYS_ROOT" \
  -subj "/CN=mirage-chaff local root" -out "$OUT/root.crt"

# --- Intermediate CA with Name Constraints ---
genkey "$OUT/intermediate.key"

# Build permitted;DNS entries for each curated suffix.
PERMITTED=""
for d in "${DOMAINS[@]}"; do
  PERMITTED+="permitted;DNS:${d}\n"
done

EXT_CNF="$(mktemp)"
trap 'rm -f "$EXT_CNF"' EXIT
{
  printf 'basicConstraints=critical,CA:TRUE,pathlen:0\n'
  printf 'keyUsage=critical,keyCertSign,cRLSign\n'
  printf 'nameConstraints=critical,@nc\n'
  printf '[nc]\n'
  printf "%b" "$PERMITTED"
} > "$EXT_CNF"

openssl req -new -key "$OUT/intermediate.key" -subj "/CN=mirage-chaff intermediate" -out "$OUT/intermediate.csr"
openssl x509 -req -in "$OUT/intermediate.csr" -CA "$OUT/root.crt" -CAkey "$OUT/root.key" \
  -CAcreateserial -sha256 -days "$DAYS_INT" -extfile "$EXT_CNF" -out "$OUT/intermediate.crt"
rm -f "$OUT/intermediate.csr"

echo "[gen-ca] wrote root + name-constrained intermediate to $OUT"
echo "[gen-ca] permitted DNS subtrees:"; printf '  %s\n' "${DOMAINS[@]}"
echo "[gen-ca] Trust $OUT/root.crt on clients. Point cert.intermediate_* at intermediate.{crt,key}."
echo "[gen-ca] NOTE: adding curated domains later requires re-issuing the intermediate."
