// Package admin is the web admin UI backend (REST + WebSocket) with argon2id
// auth, server-side sessions/CSRF, and RBAC (admin/editor/viewer). It reads/writes
// /etc/mirage-chaff config with validation and prompts SIGHUP reload;
// restart-required fields are flagged in the UI (design doc A-2).
//
// Health and metrics live in package observability, NOT here, so they survive
// admin.enabled = false (design doc A-3).
package admin
