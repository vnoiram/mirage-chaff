// Package admin is the web admin UI backend (MITM control plane): argon2id
// login, server-side sessions, CSRF, login lockout, and RBAC (admin/editor/
// viewer). It reads/writes /etc/mirage-chaff config with validation and triggers
// SIGHUP reload; restart-required fields are flagged in the UI. Health and
// metrics live in package observability, not here, so they survive
// admin.enabled=false (design doc A-3).
package admin

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/aghmanaged"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/observability"
	"github.com/vnoiram/mirage-chaff/internal/policy"
	"github.com/vnoiram/mirage-chaff/internal/rulecatalog"
)

//go:embed web
var webFS embed.FS

const sessionCookie = "mc_admin_session"

const adminMaxBodyBytes = 4 << 20

// Deps is what the admin backend needs from the running server. Passing
// functions/refs avoids an import cycle (server imports admin, not vice-versa).
type Deps struct {
	Version         string
	ConfigPath      string
	Paths           config.PathsConfig
	Recorder        *observability.Recorder
	Engine          *policy.Engine
	CertFingerprint func() string
	CertKeyType     string
	Reload          func() error
	KillSwitch      func() error
	Listeners       func() map[string]string
	OIDC            config.OIDCConfig
	SecureCookies   bool
	RuleCatalog     *rulecatalog.Store
	AGHSync         func() rulecatalog.Status
	AGHManaged      *aghmanaged.Manager
}

// Server is the admin HTTP backend.
type Server struct {
	store *Store
	sess  *sessionManager
	deps  Deps
	oidc  *oidcAuth
}

// New builds the admin server and ensures an initial admin account exists,
// printing a one-time bootstrap password to the log when it creates one. When
// OIDC is configured, provider discovery is attempted best-effort (failure is
// logged; local accounts still work).
func New(store *Store, deps Deps) *Server {
	s := &Server{store: store, sess: newSessionManager(30 * time.Minute), deps: deps}
	s.bootstrap()
	if deps.OIDC.Enabled {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if a, err := newOIDC(ctx, deps.OIDC); err != nil {
			log.Printf("admin: OIDC disabled — %v (local accounts still available)", err)
		} else {
			s.oidc = a
			log.Printf("admin: OIDC SSO enabled (issuer %s)", deps.OIDC.Issuer)
		}
	}
	return s
}

// bootstrap creates an initial admin with a random temporary password (forced
// change on first login) when the store has no users (design doc install step 5).
func (s *Server) bootstrap() {
	if s.store.UserCount() > 0 {
		return
	}
	tempPW := randToken()[:16]
	_ = s.store.Upsert(User{
		Username:   "admin",
		Hash:       HashPassword(tempPW),
		Role:       RoleAdmin,
		MustChange: true,
		Created:    time.Now(),
	})
	log.Printf("admin: created initial account 'admin' — TEMPORARY PASSWORD: %s (change on first login)", tempPW)
	s.store.Audit("system", "bootstrap", "created initial admin account")
}

// Handler returns the admin HTTP handler (API + embedded SPA).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Auth.
	mux.HandleFunc("GET /api/authinfo", s.handleAuthInfo)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.withAuth("", s.handleLogout))
	mux.HandleFunc("GET /api/me", s.withAuth("", s.handleMe))
	mux.HandleFunc("POST /api/me/password", s.withAuth("", s.handleChangePassword))
	if s.oidc != nil {
		mux.HandleFunc("GET /api/oidc/login", s.handleOIDCLogin)
		mux.HandleFunc("GET /api/oidc/callback", s.handleOIDCCallback)
	}
	if s.deps.AGHManaged != nil {
		path := s.deps.AGHManaged.Config().FeedPath
		if path == "" {
			path = "/agh/managed-rewrites.txt"
		}
		mux.HandleFunc("GET "+path, s.handleAGHManagedFeed)
	}

	// Read views.
	mux.HandleFunc("GET /api/dashboard", s.withAuth("dashboard.view", s.handleDashboard))
	mux.HandleFunc("GET /api/traffic", s.withAuth("traffic.view", s.handleTraffic))
	mux.HandleFunc("GET /api/traffic/stream", s.withAuth("traffic.view", s.handleTrafficStream))
	mux.HandleFunc("GET /api/curation", s.withAuth("policy.view", s.handleCuration))
	mux.HandleFunc("GET /api/policy", s.withAuth("policy.view", s.handlePolicyList))
	mux.HandleFunc("GET /api/policy/{name}", s.withAuth("policy.view", s.handlePolicyGet))
	mux.HandleFunc("GET /api/catalog", s.withAuth("catalog.view", s.handleCatalogList))
	mux.HandleFunc("GET /api/rule-catalog", s.withAuth("catalog.view", s.handleRuleCatalogList))
	mux.HandleFunc("GET /api/rule-catalog/{id}", s.withAuth("catalog.view", s.handleRuleCatalogGet))
	mux.HandleFunc("GET /api/rule-catalog/cname-candidates", s.withAuth("catalog.view", s.handleAnalyticsCNAMECandidates))
	mux.HandleFunc("GET /api/agh-sync/status", s.withAuth("catalog.view", s.handleAGHSyncStatus))
	mux.HandleFunc("GET /api/agh/sources", s.withAuth("catalog.view", s.handleAGHManagedSources))
	mux.HandleFunc("GET /api/agh/sources/{id}/entries", s.withAuth("catalog.view", s.handleAGHManagedSourceEntries))
	mux.HandleFunc("GET /api/agh/sources/{id}/pending-diff", s.withAuth("catalog.view", s.handleAGHManagedSourcePendingDiff))
	mux.HandleFunc("GET /api/agh/rewrite-feed/status", s.withAuth("catalog.view", s.handleAGHManagedFeedStatus))
	mux.HandleFunc("GET /api/agh/rewrite-feed/preview", s.withAuth("catalog.view", s.handleAGHManagedFeedPreview))
	mux.HandleFunc("GET /api/agh/rewrite-feed/export", s.withAuth("catalog.view", s.handleAGHManagedFeedExport))
	mux.HandleFunc("GET /api/agh/managed-catalog", s.withAuth("catalog.view", s.handleAGHManagedCatalog))
	mux.HandleFunc("GET /api/agh/managed-catalog/conflicts", s.withAuth("catalog.view", s.handleAGHManagedConflicts))
	mux.HandleFunc("GET /api/agh/managed-catalog/rollbacks", s.withAuth("catalog.view", s.handleAGHManagedRollbacks))
	mux.HandleFunc("GET /api/triage/context", s.withAuth("traffic.view", s.handleTriageContext))
	mux.HandleFunc("GET /api/analytics/summary", s.withAuth("traffic.view", s.handleAnalyticsSummary))
	mux.HandleFunc("GET /api/analytics/domains", s.withAuth("traffic.view", s.handleAnalyticsDomains))
	mux.HandleFunc("GET /api/analytics/rules", s.withAuth("traffic.view", s.handleAnalyticsRules))
	mux.HandleFunc("GET /api/analytics/catalog", s.withAuth("catalog.view", s.handleAnalyticsCatalog))
	mux.HandleFunc("GET /api/analytics/js-stubs", s.withAuth("catalog.view", s.handleAnalyticsJSStubs))
	mux.HandleFunc("GET /api/analytics/false-positive-candidates", s.withAuth("catalog.view", s.handleAnalyticsFalsePositiveCandidates))
	mux.HandleFunc("GET /api/analytics/cname-candidates", s.withAuth("catalog.view", s.handleAnalyticsCNAMECandidates))
	mux.HandleFunc("GET /api/config", s.withAuth("config.view", s.handleConfigGet))
	mux.HandleFunc("GET /api/audit", s.withAuth("audit.view", s.handleAudit))

	// Mutations.
	mux.HandleFunc("PUT /api/policy/{name}", s.withAuth("policy.edit", s.handlePolicyPut))
	mux.HandleFunc("PUT /api/config", s.withAuth("config.edit", s.handleConfigPut))
	mux.HandleFunc("POST /api/reload", s.withAuth("apply.reload", s.handleReload))
	mux.HandleFunc("POST /api/allow", s.withAuth("allow.temp", s.handleTempAllow))
	mux.HandleFunc("POST /api/triage/temp-allow", s.withAuth("allow.temp", s.handleTempAllow))
	mux.HandleFunc("POST /api/triage/permanent-allow", s.withAuth("policy.edit", s.handlePermanentAllow))
	mux.HandleFunc("POST /api/triage/site-override", s.withAuth("policy.edit", s.handleSiteOverride))
	mux.HandleFunc("POST /api/rule-catalog/{id}/review", s.withAuth("catalog.edit", s.handleRuleCatalogReview))
	mux.HandleFunc("POST /api/rule-catalog/{id}/promote", s.withAuth("catalog.edit", s.handleRuleCatalogPromote))
	mux.HandleFunc("POST /api/rule-catalog/{id}/downgrade", s.withAuth("catalog.edit", s.handleRuleCatalogDowngrade))
	mux.HandleFunc("POST /api/rule-catalog/{id}/mark-cname", s.withAuth("catalog.edit", s.handleRuleCatalogMarkCNAME))
	mux.HandleFunc("POST /api/agh/rewrite-candidate", s.withAuth("agh.manage", s.handleAGHRewriteCandidate))
	mux.HandleFunc("POST /api/agh-sync/run", s.withAuth("agh.manage", s.handleAGHSyncRun))
	mux.HandleFunc("POST /api/agh/sources", s.withAuth("agh.manage", s.handleAGHManagedSourceUpsert))
	mux.HandleFunc("POST /api/agh/sources/preview", s.withAuth("agh.manage", s.handleAGHManagedSourcePreview))
	mux.HandleFunc("PUT /api/agh/sources/{id}", s.withAuth("agh.manage", s.handleAGHManagedSourceUpsert))
	mux.HandleFunc("DELETE /api/agh/sources/{id}", s.withAuth("agh.manage", s.handleAGHManagedSourceDelete))
	mux.HandleFunc("POST /api/agh/sources/{id}/sync", s.withAuth("agh.manage", s.handleAGHManagedSourceSync))
	mux.HandleFunc("POST /api/agh/sources/{id}/approve", s.withAuth("agh.manage", s.handleAGHManagedSourceApprove))
	mux.HandleFunc("POST /api/agh/sources/{id}/reject", s.withAuth("agh.manage", s.handleAGHManagedSourceReject))
	mux.HandleFunc("POST /api/agh/managed-catalog/bulk", s.withAuth("agh.manage", s.handleAGHManagedCatalogBulkPatch))
	mux.HandleFunc("PATCH /api/agh/managed-catalog/{id}", s.withAuth("agh.manage", s.handleAGHManagedCatalogPatch))
	mux.HandleFunc("POST /api/agh/managed-catalog/conflicts/{id}/resolve", s.withAuth("agh.manage", s.handleAGHManagedConflictResolve))
	mux.HandleFunc("POST /api/agh/managed-catalog/rollbacks/{id}/apply", s.withAuth("agh.manage", s.handleAGHManagedRollbackApply))
	mux.HandleFunc("POST /api/agh/rewrite-feed/refresh-target", s.withAuth("agh.manage", s.handleAGHManagedRefreshTarget))
	mux.HandleFunc("POST /api/agh/rewrite-feed/emergency-empty", s.withAuth("agh.manage", s.handleAGHManagedEmergencyEmpty))
	mux.HandleFunc("POST /api/allow/permanent", s.withAuth("policy.edit", s.handlePermanentAllow))
	mux.HandleFunc("POST /api/site-override", s.withAuth("policy.edit", s.handleSiteOverride))
	mux.HandleFunc("POST /api/killswitch", s.withAuth("killswitch.execute", s.handleKillSwitch))

	// User management.
	mux.HandleFunc("GET /api/users", s.withAuth("users.manage", s.handleUserList))
	mux.HandleFunc("POST /api/users", s.withAuth("users.manage", s.handleUserCreate))
	mux.HandleFunc("DELETE /api/users/{name}", s.withAuth("users.manage", s.handleUserDelete))
	mux.HandleFunc("POST /api/users/{name}/password", s.withAuth("users.manage", s.handleUserSetPassword))

	// Embedded SPA.
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return s.limitBody(mux)
}

// --- middleware ---

// withAuth wraps a handler requiring a valid session and (optionally) a
// capability. State-changing methods additionally require a valid CSRF token.
func (s *Server) withAuth(capability string, h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			unauthorized(w)
			return
		}
		sess := s.sess.get(c.Value)
		if sess == nil {
			unauthorized(w)
			return
		}
		// CSRF on mutations (constant-time compare).
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
				http.Error(w, "bad CSRF token", http.StatusForbidden)
				return
			}
		}
		if s.mustChangeBlocked(sess, r) {
			http.Error(w, "password change required", http.StatusForbidden)
			return
		}
		if capability != "" && !Can(sess.role, capability) {
			http.Error(w, "forbidden: missing capability "+capability, http.StatusForbidden)
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.ContentLength > adminMaxBodyBytes {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) secureCookie(r *http.Request) bool {
	return s.deps.SecureCookies || r.TLS != nil
}

func (s *Server) mustChangeBlocked(sess *session, r *http.Request) bool {
	u, ok := s.store.Get(sess.username)
	if !ok || !u.MustChange {
		return false
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/me":
		return false
	case r.Method == http.MethodPost && r.URL.Path == "/api/me/password":
		return false
	case r.Method == http.MethodPost && r.URL.Path == "/api/logout":
		return false
	default:
		return true
	}
}

// --- auth handlers ---

// handleAuthInfo is a public endpoint telling the SPA which login methods exist.
func (s *Server) handleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"oidc": s.oidc != nil})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if s.sess.locked(req.Username) {
		http.Error(w, "account temporarily locked", http.StatusTooManyRequests)
		return
	}
	u, ok := s.store.Get(req.Username)
	// Always run a password verification (dummy hash for unknown/disabled users)
	// so response time does not reveal whether an account exists.
	hash := u.Hash
	if !ok || u.Disabled {
		hash = dummyArgonHash
	}
	if !VerifyPassword(req.Password, hash) || !ok || u.Disabled {
		// Only track failures for real accounts, so an attacker submitting random
		// usernames cannot grow the lockout map without bound.
		if ok {
			s.sess.recordFailure(req.Username)
		}
		s.store.Audit(req.Username, "login.fail", "invalid credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.sess.recordSuccess(req.Username)
	sess := s.sess.create(u.Username, u.Role)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
	s.store.Audit(u.Username, "login", "success")
	writeJSON(w, map[string]any{
		"username": u.Username, "role": u.Role, "csrf": sess.csrf, "must_change": u.MustChange,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	s.sess.destroy(sess.id)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *session) {
	u, _ := s.store.Get(sess.username)
	writeJSON(w, map[string]any{
		"username": sess.username, "role": sess.role, "csrf": sess.csrf,
		"must_change": u.MustChange, "capabilities": capList(sess.role),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Old, New string }
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if len(req.New) < 8 {
		http.Error(w, "new password must be at least 8 chars", http.StatusBadRequest)
		return
	}
	u, _ := s.store.Get(sess.username)
	if !VerifyPassword(req.Old, u.Hash) {
		http.Error(w, "old password incorrect", http.StatusUnauthorized)
		return
	}
	if err := s.store.SetPassword(sess.username, req.New); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "password.change", "self")
	writeJSON(w, map[string]string{"status": "ok"})
}

// --- helpers ---

func capList(role Role) []string {
	var out []string
	for c := range roleCaps[role] {
		out = append(out, c)
	}
	return out
}

func unauthorized(w http.ResponseWriter) { http.Error(w, "unauthorized", http.StatusUnauthorized) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		return err
	}
	return nil
}

// safeName rejects path separators so a policy filename can't escape the dir.
func safeName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..") &&
		(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"))
}

func readDirFiles(dir, suffixA, suffixB string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), suffixA) && !strings.HasSuffix(e.Name(), suffixB) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(b)
	}
	return out, nil
}
