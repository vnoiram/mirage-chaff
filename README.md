# mirage-chaff

A selective **anti-adblock / privacy "cushion" server** that sits behind
[AdGuard Home](https://adguard.com/adguard-home/overview.html) (AGH) and
intercepts only a *curated* subset of domains — the ones that break when blocked.
For those domains it terminates TLS with a dynamically issued leaf, applies a
per-domain policy, and returns plausible **decoy responses** (chaff) so
anti-adblock detection is satisfied, while trackers receive no real traffic.

The name: a **mirage** of a valid resource, made of **chaff** — decoys that
confuse the detector.

> Clients need **no proxy settings**. AGH rewrites curated domains' A/AAAA
> records to this server's IP; the client connects "directly" and lands on the
> cushion. HTTPS interception requires the client to trust the local root CA.

## How it works

```
  client ──(normal domain)──────────────▶ real server (direct)
    │ DNS
    ▼
  AdGuard Home ──(block, harmless)──▶ 0.0.0.0
    │
    └──(DNS rewrite, curated only)──▶ mirage-chaff IP
                                         │  SNI-based routing, dynamic leaf (name-constrained CA)
                                         ├─ stub ─────────▶ catalog decoy (no upstream)   [default]
                                         ├─ forward-scrubbed ▶ strip IDs → real server → reshape
                                         ├─ forward-mimic ─▶ shape-preserving decoy (img/js/bin)
                                         ├─ forward-asis ──▶ unmodified passthrough
                                         └─ passthrough ──▶ TCP/QUIC splice (pinned domains)
```

See the full design doc for the policy model, catalog format, forward-mimic and
hash-consistency engine, admin UI/RBAC, and monitoring integration.

## Requirements

- Linux + systemd, Go 1.25+ (to build)
- A running AdGuard Home you control
- An **independent** DNS resolver (must NOT be AGH — rewrite loop). Default DoH 1.1.1.1.
- Clients must trust the local root CA (see `deploy/gen-ca.sh`)

## Build & install

```sh
make build                 # -> bin/mirage-chaff
make check                 # validate the sample config (nginx -t style)
sudo ./deploy/install.sh   # build + user + dirs + sample config + systemd unit (idempotent)
```

## Operate

```sh
sudo systemctl start   mirage-chaff
sudo systemctl reload  mirage-chaff     # SIGHUP: hot-reload policy.d/catalog only
sudo systemctl restart mirage-chaff     # needed for listener/protocol/cert changes
journalctl -u mirage-chaff -f
curl -s http://127.0.0.1:9256/-/healthy # health (works even when admin is disabled)
```

**Reload vs restart:** policy.d, catalog, `mimic.*`, `log.*`, `rate_limit`,
`mode` (stub side) apply on `reload`. Listener addresses/ports, `protocols.*`,
`cert.key_type`, `admin.*`, and `observability.*` binds require `restart` (socket
rebind). `mirage-chaff check` validates before you apply either.

## Setup checklist

1. **Intermediate CA (name-constrained):**
   `deploy/gen-ca.sh -d .doubleclick.net -d .googlesyndication.com …`
   Trust `ca/root.crt` on clients. The intermediate is restricted to the curated
   domains so a compromise can't mint certs for arbitrary sites.
2. **AGH rewrites:** add A/AAAA rewrites for curated domains → this host, wrapped
   in the cushion marker block so the kill-switch can find them. **Start
   mirage-chaff before adding rewrites**, or those domains break.
3. **QUIC:** default off. Block UDP/443 so clients fall back to TCP:
   `sudo deploy/firewall-udp443.sh block`.
4. **Client DoH/ECH:** disable browser Secure DNS / ECH, or clients bypass AGH
   and the cushion entirely.

## Emergency revert

```sh
sudo ./deploy/kill-switch.sh   # remove cushion rewrites from AGH → normal resolution
```

## Security notes

- The intermediate CA is a live MITM authority. Protect the key (0600, dedicated
  user, VM isolation) and keep the **Name Constraints** in place.
- The admin UI is a MITM control plane: localhost-bound, authenticated (argon2id),
  RBAC (admin/editor/viewer). Off by default.
- Cert cache is keyed by the intermediate CA fingerprint and purged on rotation.

## Repository layout

```
cmd/mirage-chaff/   entry point (run / check / version)
internal/           config, certgen, policy, catalog, stub, forward, mimic,
                    hashrewrite, passthrough, quic, server, observability, admin
web/                admin UI SPA (embedded; Phase 6)
configs/            sample config + example policy + catalog (tracked)
deploy/             systemd unit, install/uninstall, kill-switch, gen-ca, firewall
```

Only source and **sample** configs are tracked. Real `/etc/mirage-chaff` config,
CA keys, cert cache, and admin state are **not** in this repo (see `.gitignore`).

## Status

Phase 0 skeleton: runnable binary with config load/validate and an
admin-independent health/metrics listener. The TLS interception data path,
policy engine, mimic, admin UI, and monitoring integration land in later phases
(see the design doc's phased rollout).

## License

MIT — see [LICENSE](LICENSE).
