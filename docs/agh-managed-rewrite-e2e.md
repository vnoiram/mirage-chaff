# AGH Managed Rewrite E2E Check

This check verifies that a managed rewrite feed is reachable, registered in
AdGuard Home (AGH), and selected by AGH for a real domain candidate.

## Prerequisites

- `agh_managed_rewrites.enabled = true`.
- The managed feed URL is reachable from the host running the check.
- The feed already contains `CHECK_DOMAIN`.
- AGH API credentials are available.
- The feed is registered in AGH DNS blocklists. Use the admin UI Feed Setup
  `Register in AGH` button, or add the URL manually in AGH.
- `curl` and `jq` are installed.
- `dig` is installed when using optional `AGH_DNS_SERVER` DNS listener checks
  or `CLIENT_DNS_CHECK=true`.

## Run

```sh
AGH_API_URL=http://127.0.0.1:3000 \
AGH_API_USER=admin \
AGH_API_PASS=secret \
MIRAGE_FEED_URL=https://mirage.example.lan/agh/managed-rewrites.txt \
CHECK_DOMAIN=tracker.example.net \
deploy/agh-managed-e2e-check.sh
```

If the AGH filter cache may be stale, allow the script to request a refresh:

```sh
FORCE_REFRESH=true \
AGH_API_URL=http://127.0.0.1:3000 \
AGH_API_USER=admin \
AGH_API_PASS=secret \
MIRAGE_FEED_URL=https://mirage.example.lan/agh/managed-rewrites.txt \
CHECK_DOMAIN=tracker.example.net \
deploy/agh-managed-e2e-check.sh
```

For lab environments with self-signed TLS on the feed or AGH endpoint, add
`INSECURE_TLS=true`.

If the target IP is known, add `EXPECTED_TARGET_IP=192.0.2.10` to verify that AGH
reports the expected rewrite target.

To also verify the AGH DNS listener, add `AGH_DNS_SERVER`. This uses `dig` and
queries AGH directly, bypassing local resolver configuration:

```sh
AGH_DNS_SERVER=127.0.0.1 \
EXPECTED_TARGET_IP=192.0.2.10 \
AGH_API_URL=http://127.0.0.1:3000 \
AGH_API_USER=admin \
AGH_API_PASS=secret \
MIRAGE_FEED_URL=https://mirage.example.lan/agh/managed-rewrites.txt \
CHECK_DOMAIN=tracker.example.net \
deploy/agh-managed-e2e-check.sh
```

Use `AGH_DNS_PORT` when AGH listens on a non-default DNS port. Use `DNS_QTYPE`
to check `AAAA` or another record type.

To verify the normal resolver path from the machine running the script, add
`CLIENT_DNS_CHECK=true`. This does not force AGH directly; it checks what the
client host would resolve through its configured DNS path:

```sh
CLIENT_DNS_CHECK=true \
EXPECTED_TARGET_IP=192.0.2.10 \
AGH_API_URL=http://127.0.0.1:3000 \
AGH_API_USER=admin \
AGH_API_PASS=secret \
MIRAGE_FEED_URL=https://mirage.example.lan/agh/managed-rewrites.txt \
CHECK_DOMAIN=tracker.example.net \
deploy/agh-managed-e2e-check.sh
```

## What It Checks

1. Fetches `MIRAGE_FEED_URL`.
2. Confirms the feed contains the `! mirage-chaff managed rewrites` header.
3. Confirms the feed contains `CHECK_DOMAIN` and at least one `$dnsrewrite` rule.
4. Calls AGH `GET /control/filtering/status`.
5. Confirms the feed URL is registered and enabled in AGH DNS blocklists.
6. Optionally calls AGH `POST /control/filtering/refresh` when
   `FORCE_REFRESH=true`.
7. Calls AGH `GET /control/filtering/check_host?name=CHECK_DOMAIN`.
8. Confirms AGH reports a rewrite/filter match for the domain.
9. If `AGH_DNS_SERVER` is set, queries AGH with `dig` and verifies the DNS
   answer.
10. If `CLIENT_DNS_CHECK=true`, queries the host's default resolver path with
    `dig` and verifies the DNS answer.

The script does not add or remove AGH filters. The only AGH-side mutation it can
perform is a filter refresh when `FORCE_REFRESH=true`.

`check_host` verifies AGH's filtering decision path. `AGH_DNS_SERVER` verifies
that the AGH DNS listener returns an answer for the same domain. `CLIENT_DNS_CHECK`
verifies the default resolver path from the script host. Client browsers may
still bypass AGH via Secure DNS, ECH, VPNs, or cached DNS answers.

## Exit Codes

- `0`: pass.
- `2`: missing input or required tool.
- `3`: feed fetch or feed content failure.
- `4`: AGH registration or refresh failure.
- `5`: AGH `check_host` or a DNS resolver check did not confirm the rewrite.

## Failure Triage

| Failing step | What it usually means | Checks |
| --- | --- | --- |
| Feed fetch / content | mirage-chaff feed URL, route, or TLS trust is wrong | Open the feed URL from the AGH host; confirm the header, `CHECK_DOMAIN`, `$dnsrewrite`, target mode, emergency empty, and excluded reasons in feed preview |
| AGH registration | AGH is not subscribed to the feed, the list is disabled, or API credentials point to the wrong instance | Use Feed Setup `Register in AGH`, then `Check AGH registration`; confirm `AGH_API_URL`, `AGH_API_USER`, `AGH_API_PASS`, and blocklist enabled state |
| AGH refresh | AGH cannot refresh filters or cannot fetch the feed with its own network/TLS context | Retry with `FORCE_REFRESH=true`; check AGH logs, rate limits, route to `MIRAGE_FEED_URL`, and AGH trust store |
| `check_host` | AGH has not selected the managed rewrite for `CHECK_DOMAIN` | Refresh filters; confirm the feed contains the domain; check for higher-priority AGH rules, stale filter cache, and expected target IP mismatch |
| AGH DNS listener | AGH's API decision path works, but the DNS listener path does not | Confirm `AGH_DNS_SERVER:AGH_DNS_PORT`, firewall rules, listener bind settings, query type, and AGH DNS cache |
| Client resolver | AGH works directly, but the client host does not resolve through AGH | Clear OS DNS cache; check resolver settings, VPN routing, Secure DNS, ECH/TLS trust, and browser-level DNS bypass |
