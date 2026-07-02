# web/ — admin UI SPA

The admin UI single-page app lives here and is compiled into the Go binary via
`embed.FS` (single-binary distribution, no extra runtime). Implemented in Phase 6.

Backend: `internal/admin` (REST + WebSocket, argon2id auth, RBAC admin/editor/viewer).
Health and metrics are **not** served here — they live in `internal/observability`
so they survive `admin.enabled = false` (design doc A-3).
