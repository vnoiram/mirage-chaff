package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/policy"
)

// handleDashboard returns at-a-glance status (design doc screen 1).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sess *session) {
	rs := s.deps.Engine.Ruleset()
	listeners := map[string]string{}
	if s.deps.Listeners != nil {
		listeners = s.deps.Listeners()
	}
	fp := ""
	if s.deps.CertFingerprint != nil {
		fp = s.deps.CertFingerprint()
	}
	writeJSON(w, map[string]any{
		"version":          s.deps.Version,
		"listeners":        listeners,
		"policy_rules":     len(rs.Rules()),
		"cert_fingerprint": fp,
		"cert_key_type":    s.deps.CertKeyType,
		"temp_allows":      s.deps.Engine.TempRules(),
		"users":            s.store.UserCount(),
	})
}

// handleTraffic returns the recent traffic ring buffer (redacted per policy).
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, s.deps.Recorder.Snapshot(500))
}

// handleTrafficStream streams live records via Server-Sent Events.
func (s *Server) handleTrafficStream(w http.ResponseWriter, r *http.Request, sess *session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")

	seq := s.deps.Recorder.Seq()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			recs, next := s.deps.Recorder.SnapshotSince(seq)
			if len(recs) > 0 {
				for _, rec := range recs {
					b, _ := json.Marshal(rec)
					fmt.Fprintf(w, "data: %s\n\n", b)
				}
				flusher.Flush()
			}
			seq = next
		}
	}
}

// handleCuration returns the top unmatched domains/paths (rule candidates).
func (s *Server) handleCuration(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, s.deps.Engine.UnmatchedTop(100))
}

func (s *Server) handlePolicyList(w http.ResponseWriter, r *http.Request, sess *session) {
	files, err := readDirFiles(s.deps.Paths.PolicyDir, ".yaml", ".yml")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	writeJSON(w, map[string]any{"files": names})
}

func (s *Server) handlePolicyGet(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !safeName(name) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.deps.Paths.PolicyDir, name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{"name": name, "content": string(b)})
}

func (s *Server) handlePolicyPut(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !safeName(name) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	var req struct{ Content string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Validate before writing (design doc D-2: never persist a broken ruleset).
	if err := policy.ValidateBytes([]byte(req.Content)); err != nil {
		http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.WriteFile(filepath.Join(s.deps.Paths.PolicyDir, name), []byte(req.Content), 0o640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "policy.edit", name)
	writeJSON(w, map[string]string{"status": "ok", "note": "call /api/reload to apply"})
}

func (s *Server) handleCatalogList(w http.ResponseWriter, r *http.Request, sess *session) {
	entries, err := os.ReadDir(s.deps.Paths.CatalogDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	writeJSON(w, map[string]any{"files": names})
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request, sess *session) {
	b, err := os.ReadFile(s.deps.ConfigPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"path": s.deps.ConfigPath, "content": string(b)})
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Content string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Validate by loading into a temp file and running Check().
	tmp, err := os.CreateTemp("", "mc-conf-*.toml")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString(req.Content)
	tmp.Close()
	cfg, err := config.Load(tmp.Name())
	if err == nil {
		err = cfg.Check()
	}
	if err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 0600: the config can hold secrets (e.g. OIDC client_secret), so keep it
	// owner-only. WriteFile's mode applies on create; Chmod enforces it on an
	// existing file too.
	if err := os.WriteFile(s.deps.ConfigPath, []byte(req.Content), 0o600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = os.Chmod(s.deps.ConfigPath, 0o600)
	s.store.Audit(sess.username, "config.edit", s.deps.ConfigPath)
	writeJSON(w, map[string]string{"status": "ok", "note": "restart-required fields need a service restart"})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.Reload == nil {
		http.Error(w, "reload unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.deps.Reload(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "reload", "SIGHUP")
	writeJSON(w, map[string]string{"status": "reloaded"})
}

func (s *Server) handleTempAllow(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Domain  string `json:"domain"`
		Minutes int    `json:"minutes"`
		Action  string `json:"action"` // default forward-asis
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Minutes <= 0 || req.Minutes > 240 {
		req.Minutes = 15
	}
	action := req.Action
	if action == "" {
		action = policy.ActionForwardAsis
	}
	s.deps.Engine.AddTempRule(req.Domain, action, "", time.Duration(req.Minutes)*time.Minute)
	s.store.Audit(sess.username, "allow.temp", fmt.Sprintf("%s for %dm (%s)", req.Domain, req.Minutes, action))
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.KillSwitch == nil {
		http.Error(w, "kill-switch unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.deps.KillSwitch(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "killswitch.execute", "AGH rewrites removed")
	writeJSON(w, map[string]string{"status": "kill-switch executed"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, s.store.AuditLog(500))
}

// --- user management ---

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, s.store.List())
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Username, Password string
		Role               Role
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || len(req.Password) < 8 {
		http.Error(w, "username and password (>=8 chars) required", http.StatusBadRequest)
		return
	}
	if _, ok := roleCaps[req.Role]; !ok {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	if _, exists := s.store.Get(req.Username); exists {
		http.Error(w, "user exists", http.StatusConflict)
		return
	}
	if err := s.store.Upsert(User{Username: req.Username, Hash: HashPassword(req.Password), Role: req.Role, Created: time.Now()}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "users.create", req.Username+" ("+string(req.Role)+")")
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if name == sess.username {
		http.Error(w, "cannot delete yourself", http.StatusBadRequest)
		return
	}
	if err := s.store.Delete(name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sess.destroyUser(name)
	s.store.Audit(sess.username, "users.delete", name)
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleUserSetPassword(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Password) < 8 {
		http.Error(w, "password must be at least 8 chars", http.StatusBadRequest)
		return
	}
	if err := s.store.SetPassword(name, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.sess.destroyUser(name)
	s.store.Audit(sess.username, "users.setpassword", name)
	writeJSON(w, map[string]string{"status": "ok"})
}
