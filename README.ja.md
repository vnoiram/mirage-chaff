# mirage-chaff

[AdGuard Home](https://adguard.com/adguard-home/overview.html) (AGH) の背後に置く、選択的な **anti-adblock / privacy "cushion" server** です。ブロックすると壊れる、厳選された一部 domain だけを intercept します。対象 domain では動的に発行した leaf certificate で TLS を終端し、domain ごとの policy を適用し、もっともらしい **decoy response** (chaff) を返します。これにより anti-adblock detection を満たしつつ、tracker には実 traffic を送りません。

名前の由来は、有効な resource の **mirage** を **chaff**、つまり detector を混乱させる decoy で作ることです。

> client に **proxy 設定は不要** です。AGH が curated domain の A/AAAA record をこの server の IP に rewrite します。client は「直接」接続しているつもりで cushion に到達します。HTTPS interception には、client が local root CA を信頼する必要があります。

## 仕組み

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

policy model、catalog format、forward-mimic と hash-consistency engine、admin UI/RBAC、monitoring integration については完全な design doc を参照してください。

## 要件

- Linux + systemd、Go 1.25+ (build 用)
- 自分で管理している AdGuard Home
- **独立した** DNS resolver (AGH では不可。rewrite loop になります)。既定 DoH は 1.1.1.1。
- client が local root CA を信頼すること (`deploy/gen-ca.sh` を参照)

## Build & install

```sh
make build                 # -> bin/mirage-chaff
make check                 # sample config を検証 (nginx -t 風)
sudo ./deploy/install.sh   # build + user + dirs + sample config + systemd unit (idempotent)
```

## 運用

```sh
sudo systemctl start   mirage-chaff
sudo systemctl reload  mirage-chaff     # SIGHUP: policy.d/catalog の hot-reload のみ
sudo systemctl restart mirage-chaff     # listener/protocol/cert 変更に必要
journalctl -u mirage-chaff -f
curl -s http://127.0.0.1:9256/-/healthy # health (admin disabled でも動作)
```

**reload と restart:** policy.d, catalog, `mimic.*`, `log.*`, `rate_limit`, `mode` (stub 側) は `reload` で適用されます。listener address/port、`protocols.*`、`cert.key_type`、`admin.*`、`observability.*` bind は `restart` が必要です。適用前には `mirage-chaff check` で検証してください。

## セットアップチェックリスト

1. **Intermediate CA (name-constrained):**
   `deploy/gen-ca.sh -d .doubleclick.net -d .googlesyndication.com ...`
   client で `ca/root.crt` を信頼します。intermediate は curated domain に制限されるため、侵害されても任意 site の証明書は発行できません。
2. **AGH rewrites:** curated domain の A/AAAA rewrite をこの host に追加します。kill-switch が見つけられるよう cushion marker block で囲みます。**rewrite 追加前に mirage-chaff を起動してください**。そうしないと対象 domain が壊れます。managed rewrite feed では、`docs/agh-managed-rewrite-e2e.md` で AGH registration と DNS rewrite behavior を確認します。
3. **QUIC:** 既定では off。client が TCP に fallback するよう UDP/443 を block します: `sudo deploy/firewall-udp443.sh block`。
4. **Client DoH/ECH:** browser Secure DNS / ECH を無効化してください。有効だと client が AGH と cushion を迂回します。

## 緊急復旧

```sh
sudo ./deploy/kill-switch.sh   # cushion rewrite を AGH から削除し通常解決へ戻す
```

## セキュリティ注意

- intermediate CA は有効な MITM authority です。key を保護し (0600、専用 user、VM isolation)、**Name Constraints** を維持してください。
- admin UI は MITM control plane です。localhost bind、認証 (argon2id)、RBAC (admin/editor/viewer)。既定は off です。
- cert cache は intermediate CA fingerprint を key にし、rotation 時に purge されます。

## リポジトリ構成

```
cmd/mirage-chaff/   entry point (run / check / version)
internal/           config, certgen, policy, catalog, stub, forward, mimic,
                    hashrewrite, passthrough, quic, server, observability, admin
web/                admin UI SPA (embedded)
configs/            sample config + example/curated policy + catalog (tracked)
deploy/             systemd unit, install/uninstall, kill-switch, gen-ca,
                    step-ca-issue, firewall, monitoring/, wazuh/, ansible/
```

source と **sample** config だけを track しています。実際の `/etc/mirage-chaff` config、CA key、cert cache、admin state はこの repo には含まれません (`.gitignore` を参照)。

## 状態

段階的 milestone はすべて実装済みです (design doc の rollout 参照)。

1. **TLS interception**: name-constrained intermediate CA から SNI ごとの dynamic leaf を発行 (`internal/certgen`)、catalog decoy、stub action。
2. **Policy engine**: `policy.d` matcher、unmatched-domain curation、dual-stack。
3. **Forward + passthrough**: independent resolver (DoH/DoT/plain) 経由の scrubbed/asis reverse-proxy、SNI-peek TCP splice、redacted observability。
4. **forward-mimic**: Range support 付き deterministic image/js/binary decoy、SRI/JSON `hashrewrite`、opt-in opaque video-shaped decoy。
5. **QUIC**: HTTP/3 termination (quic-go)、from-scratch RFC 9001 Initial SNI parser、UDP passthrough relay、`sd_notify` watchdog、circuit breaker。
6. **Admin UI**: argon2id + sessions + CSRF + lockout + RBAC、embedded SPA、live traffic、editor、temporary-allow、kill-switch、audit。
7. **Monitoring**: Prometheus `/metrics`、Alertmanager rules、promtail->Loki、Grafana dashboard、health/synthetic probe (`deploy/monitoring/`)。
8. **Deployment**: step-ca issuance、admin OIDC SSO、Ansible role、Wazuh SOC feed。

注意: admin user/audit store は 0600 JSON file です (SQLite が documented production target)。QUIC passthrough は best-effort per C-2 で、既定では off です。

## ライセンス

MIT。詳細は [LICENSE](LICENSE) を参照してください。
