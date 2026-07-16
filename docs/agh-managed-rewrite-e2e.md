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
- `dig` is installed when using optional `AGH_DNS_SERVER` DNS listener checks.

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

The script does not add or remove AGH filters. The only AGH-side mutation it can
perform is a filter refresh when `FORCE_REFRESH=true`.

`check_host` verifies AGH's filtering decision path. The optional `dig` check
verifies that the DNS listener returns an answer for the same domain. Client
browsers may still bypass AGH via Secure DNS, ECH, VPNs, or cached DNS answers.

## Exit Codes

- `0`: pass.
- `2`: missing input or required tool.
- `3`: feed fetch or feed content failure.
- `4`: AGH registration or refresh failure.
- `5`: AGH `check_host` did not confirm the rewrite/filter match.

## Failure Triage

- Exit `3`: open the feed URL from the AGH host and confirm the response starts
  with `! mirage-chaff managed rewrites`. Then confirm the chosen domain is
  included in feed preview and not excluded by conflict, preset, review status,
  stale source policy, or emergency empty.
- Exit `4`: use Feed Setup in the admin UI. Run `Register in AGH`, then
  `Check AGH registration`. Confirm `AGH_API_URL`, `AGH_API_USER`, and
  `AGH_API_PASS` point to the intended AGH instance.
- Exit `5`: refresh AGH filters, then check the domain again. If
  `EXPECTED_TARGET_IP` is set, confirm the feed target mode and resolved/static
  target IPs match that value. When the AGH API check passes but the optional
  DNS query fails, confirm AGH is listening on `AGH_DNS_SERVER:AGH_DNS_PORT`,
  clear AGH/client DNS caches, and verify the client is not bypassing AGH with
  Secure DNS, ECH, VPN routing, or a different resolver.
