# mirage-chaff — monitoring integration

Drop-in artifacts to wire mirage-chaff into the existing monitoring stack
(`your ops repo`) without inventing new mechanisms. Everything reuses the
deployment's Prometheus / Alertmanager / Loki / Grafana / Uptime Kuma conventions.

| File | Where it goes | Purpose |
|---|---|---|
| `prometheus-scrape.yml` | prometheus.yml / `prometheus_targets` | scrape `/metrics` (§2) |
| `mirage-chaff_alerts.yml` | `roles/prometheus/files/` | Alertmanager rules → ntfy/Discord (§3) |
| `promtail-scrape.yml` | promtail config | ship journald JSON to Loki, redacted (§4) |
| `grafana-dashboard.json` | Grafana → Import | operator dashboard (Prometheus + Loki) (§5) |

## Health / synthetic probe (§6 — Uptime Kuma + Blackbox)

mirage-chaff serves, on the observability listener (default `:9256`), independent
of the admin UI:

- `GET /-/healthy` — liveness (process up)
- `GET /ready` — readiness (data path bound)
- `GET /metrics` — Prometheus

**Uptime Kuma**: add an HTTP(s) monitor for `http://cushion.example.com:9256/-/healthy`.

**Blackbox `http_2xx`**: probe `/ready`. Add to `blackbox_targets`.

**Functional synthetic probe** (verifies the *interception path*, not just the
process): from a host that trusts the root CA and resolves a known test domain to
the cushion, fetch a URL you have curated to a known decoy and assert the
response. Example Blackbox module + target:

```yaml
# blackbox.yml
modules:
  mirage_chaff_decoy:
    prober: http
    http:
      valid_status_codes: [204]
      fail_if_body_matches_regexp: ["real-ad-marker"]
      tls_config: { ca_file: /etc/ssl/certs/mirage-chaff-root.crt }
# targets: https://ads.test.example/known-beacon  (AGH-rewritten to the cushion)
```

This catches "process alive but interception broken" — e.g. CA expired, policy
not loaded, or upstream loop.

## Notes

- **Redaction happens before Loki.** `log.redact = true` masks query values and
  sensitive headers in the log line itself, so aggregated logs never carry raw
  identifiers.
- `/metrics` and health are **not** gated by `admin.enabled`, so monitoring keeps
  working on constrained VMs with the admin UI off (design doc A-3).
- Cert-expiry alerting uses `mirage_chaff_intermediate_ca_not_after_seconds`; pair
  with the rotation runbook in the main README.
