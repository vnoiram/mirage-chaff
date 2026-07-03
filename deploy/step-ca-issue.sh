#!/usr/bin/env bash
# step-ca-issue.sh — obtain the mirage-chaff intermediate CA from an existing
# step-ca (your step-ca host, design doc §1), replacing the manual
# gen-ca.sh. The daemon's leaf-issuance logic is unchanged: it just loads the
# intermediate cert+key from /etc/mirage-chaff/ca/.
#
# The intermediate is signed by the step-ca root that ca_trust already distributes
# to your hosts, so clients trust it without extra steps. It MUST keep the Name
# Constraints limiting issuance to curated domains (design doc B-1).
#
# Prereqs: `step` CLI configured against your step-ca; a provisioner permitted to
# issue intermediate (CA) certificates with name constraints.
#
# Usage:
#   deploy/step-ca-issue.sh -d .doubleclick.net -d .googlesyndication.com
set -euo pipefail

OUT="${OUT:-/etc/mirage-chaff/ca}"
KTY="${KTY:-EC}"                 # EC (P-256) | RSA
DUR="${DUR:-8760h}"             # 1 year
PROVISIONER="${STEP_PROVISIONER:-mirage-chaff}"
DOMAINS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain) DOMAINS+=("$2"); shift 2 ;;
    -o|--out) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ "${#DOMAINS[@]}" -gt 0 ] || { echo "at least one -d <domain-suffix> is required" >&2; exit 2; }
command -v step >/dev/null || { echo "'step' CLI not found" >&2; exit 1; }

mkdir -p "$OUT"; chmod 700 "$OUT"

# Build the permitted-DNS template fragment for step-ca (x509 nameConstraints).
NC=""
for d in "${DOMAINS[@]}"; do NC="${NC}\"${d}\","; done
NC="${NC%,}"

cat > "$OUT/intermediate.tpl" <<EOF
{
  "subject": {"commonName": "mirage-chaff intermediate"},
  "keyUsage": ["certSign", "crlSign"],
  "basicConstraints": {"isCA": true, "maxPathLen": 0},
  "nameConstraints": {"critical": true, "permittedDNSDomains": [${NC}]}
}
EOF

# Issue the intermediate CA from step-ca using the template.
step ca certificate "mirage-chaff intermediate" \
  "$OUT/intermediate.crt" "$OUT/intermediate.key" \
  --provisioner "$PROVISIONER" \
  --template "$OUT/intermediate.tpl" \
  --kty "$KTY" --not-after "$DUR" \
  --ca-url "${STEP_CA_URL:-https://step-ca.example.com:9000}"

chmod 600 "$OUT/intermediate.key"
echo "[step-ca] intermediate written to $OUT (name-constrained to: ${DOMAINS[*]})"
echo "[step-ca] clients already trust the step-ca root via ca_trust; no extra step."
echo "[step-ca] point cert.intermediate_cert/key at $OUT/intermediate.{crt,key} and restart."
echo "[step-ca] rotation: re-run before expiry; certcache auto-purges on CA change (B-2)."
