#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'USAGE'
Usage:
  AGH_API_URL=http://127.0.0.1:3000 \
  AGH_API_USER=admin \
  AGH_API_PASS=secret \
  MIRAGE_FEED_URL=https://mirage.example/agh/managed-rewrites.txt \
  CHECK_DOMAIN=tracker.example.net \
  deploy/agh-managed-e2e-check.sh

Optional:
  EXPECTED_TARGET_IP=192.0.2.10
  FORCE_REFRESH=true
  INSECURE_TLS=true
  AGH_DNS_SERVER=127.0.0.1
  AGH_DNS_PORT=53
  DNS_QTYPE=A

Exit codes:
  0 pass
  2 input/tooling error
  3 feed fetch/content failure
  4 AGH registration failure
  5 AGH check_host/rewrite failure
USAGE
}

fail() {
  local code="$1"
  shift
  printf 'FAIL: %s\n' "$*" >&2
  exit "${code}"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    fail 2 "${name} is required"
  fi
}

bool_env() {
  local value="${1:-false}"
  [[ "${value}" == "true" || "${value}" == "1" || "${value}" == "yes" ]]
}

curl_args=(-fsS)
if bool_env "${INSECURE_TLS:-false}"; then
  curl_args+=(-k)
fi

agh_json() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local url="${AGH_API_URL%/}${path}"
  if [[ -n "${body}" ]]; then
    curl "${curl_args[@]}" -u "${AGH_API_USER}:${AGH_API_PASS}" \
      -H 'Content-Type: application/json' \
      -X "${method}" \
      --data "${body}" \
      "${url}"
  else
    curl "${curl_args[@]}" -u "${AGH_API_USER}:${AGH_API_PASS}" \
      -X "${method}" \
      "${url}"
  fi
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

for tool in curl jq; do
  command -v "${tool}" >/dev/null || fail 2 "${tool} is required"
done

require_env AGH_API_URL
require_env AGH_API_USER
require_env AGH_API_PASS
require_env MIRAGE_FEED_URL
require_env CHECK_DOMAIN

printf '==> Fetching managed rewrite feed\n'
feed="$(curl "${curl_args[@]}" "${MIRAGE_FEED_URL}")" || fail 3 "could not fetch MIRAGE_FEED_URL"
grep -Fq '! mirage-chaff managed rewrites' <<<"${feed}" || fail 3 "feed header is missing"
grep -Fq "${CHECK_DOMAIN}" <<<"${feed}" || fail 3 "CHECK_DOMAIN is not present in feed"
grep -Fq '$dnsrewrite=' <<<"${feed}" || fail 3 "feed has no dnsrewrite rules"
printf 'OK: feed fetched and contains %s\n' "${CHECK_DOMAIN}"

printf '==> Checking AGH filter registration\n'
status="$(agh_json GET /control/filtering/status)" || fail 4 "could not query AGH filtering status"
registered_filter="$(jq -r --arg url "${MIRAGE_FEED_URL%/}" '
  (.filters // [])
  | map(select((.url | rtrimstr("/")) == $url))
  | first // empty
' <<<"${status}")"
if [[ -z "${registered_filter}" ]]; then
  fail 4 "managed feed URL is not registered in AGH DNS blocklists"
fi
enabled="$(jq -r '.enabled // false' <<<"${registered_filter}")"
if [[ "${enabled}" != "true" ]]; then
  fail 4 "managed feed URL is registered but disabled"
fi
filter_name="$(jq -r '.name // .url // "matched filter"' <<<"${registered_filter}")"
printf 'OK: registered and enabled in AGH: %s\n' "${filter_name}"

if bool_env "${FORCE_REFRESH:-false}"; then
  printf '==> Refreshing AGH filters\n'
  agh_json POST /control/filtering/refresh '{"force":true}' >/dev/null || fail 4 "AGH filter refresh failed"
  printf 'OK: AGH refresh requested\n'
fi

printf '==> Checking AGH host decision\n'
check_path="/control/filtering/check_host?name=$(jq -rn --arg v "${CHECK_DOMAIN}" '$v|@uri')"
check="$(agh_json GET "${check_path}")" || fail 5 "AGH check_host failed"
check_text="$(jq -r '[.reason, .rule, (.rules // [] | map(.text) | join(" ")), (.ip_addrs // [] | join(" ")), .cname] | map(select(. != null and . != "")) | join(" ")' <<<"${check}")"
if ! grep -Fq '$dnsrewrite=' <<<"${check_text}" && ! grep -Eq 'Rewrite|Rewritten|Filtered' <<<"${check_text}"; then
  fail 5 "AGH check_host did not report a rewrite/filter match: ${check_text}"
fi
if [[ -n "${EXPECTED_TARGET_IP:-}" ]] && ! grep -Fq "${EXPECTED_TARGET_IP}" <<<"${check_text}"; then
  fail 5 "EXPECTED_TARGET_IP was not present in AGH check_host result"
fi
printf 'OK: AGH check_host matched managed rewrite for %s\n' "${CHECK_DOMAIN}"

if [[ -n "${AGH_DNS_SERVER:-}" ]]; then
  command -v dig >/dev/null || fail 2 "dig is required when AGH_DNS_SERVER is set"
  dns_port="${AGH_DNS_PORT:-53}"
  dns_qtype="${DNS_QTYPE:-A}"
  printf '==> Querying AGH DNS listener\n'
  dns_answer="$(dig @"${AGH_DNS_SERVER}" -p "${dns_port}" "${CHECK_DOMAIN}" "${dns_qtype}" +short)" || fail 5 "DNS query to AGH failed"
  if [[ -z "${dns_answer}" ]]; then
    fail 5 "DNS query to AGH returned no answers"
  fi
  if [[ -n "${EXPECTED_TARGET_IP:-}" ]] && ! grep -Fxq "${EXPECTED_TARGET_IP}" <<<"${dns_answer}"; then
    fail 5 "EXPECTED_TARGET_IP was not present in DNS answer: ${dns_answer//$'\n'/, }"
  fi
  printf 'OK: AGH DNS listener answered %s %s: %s\n' "${CHECK_DOMAIN}" "${dns_qtype}" "${dns_answer//$'\n'/, }"
fi

printf 'PASS: AGH managed rewrite E2E check passed\n'
