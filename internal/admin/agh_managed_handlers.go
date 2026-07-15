package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/aghmanaged"
	"github.com/vnoiram/mirage-chaff/internal/config"
)

func (s *Server) handleAGHManagedFeed(w http.ResponseWriter, r *http.Request) {
	if s.deps.AGHManaged == nil {
		http.NotFound(w, r)
		return
	}
	p, err := s.deps.AGHManaged.Generate(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(p.Lines))
}

func (s *Server) handleAGHManagedSources(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"sources": s.deps.AGHManaged.ListSources()})
}

func (s *Server) handleAGHManagedSourceUpsert(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req aghmanaged.Source
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if id := r.PathValue("id"); id != "" {
		req.ID = id
	}
	src, err := s.deps.AGHManaged.UpsertSource(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.source.upsert", aghManagedSourceAuditDetail(src))
	writeJSON(w, src)
}

func (s *Server) handleAGHManagedSourcePreview(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req aghmanaged.Source
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	src, entries, err := s.deps.AGHManaged.PreviewSource(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"source": src, "entries": entries})
}

func (s *Server) handleAGHManagedSourceDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "source id required", http.StatusBadRequest)
		return
	}
	if err := s.deps.AGHManaged.DeleteSource(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "agh_managed.source.delete", "id="+id)
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleAGHManagedSourceSync(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	src, err := s.deps.AGHManaged.SyncSource(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.source.sync", aghManagedSourceSyncAuditDetail(src))
	writeJSON(w, src)
}

func (s *Server) handleAGHManagedSourceApprove(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	src, err := s.deps.AGHManaged.ApproveSource(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.source.approve", aghManagedSourceAuditDetail(src))
	writeJSON(w, src)
}

func (s *Server) handleAGHManagedSourceReject(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	src, err := s.deps.AGHManaged.RejectSource(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.source.reject", aghManagedSourceAuditDetail(src))
	writeJSON(w, src)
}

func (s *Server) handleAGHManagedSourcePendingDiff(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	diff, err := s.deps.AGHManaged.PendingDiff(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, diff)
}

func (s *Server) handleAGHManagedSourceEntries(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	entries, err := s.deps.AGHManaged.SourceEntries(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, src := range s.deps.AGHManaged.ListSources() {
		if src.ID == id {
			writeJSON(w, map[string]any{"source": src, "entries": entries})
			return
		}
	}
	http.Error(w, os.ErrNotExist.Error(), http.StatusNotFound)
}

func (s *Server) handleAGHManagedCatalog(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"entries": s.deps.AGHManaged.CatalogRows()})
}

func (s *Server) handleAGHManagedConflicts(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"conflicts": s.deps.AGHManaged.ListConflicts()})
}

func (s *Server) handleAGHManagedRollbacks(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"rollbacks": s.deps.AGHManaged.ListRollbacks()})
}

type aghManagedHistoryEvent struct {
	Time           time.Time `json:"time"`
	Kind           string    `json:"kind"`
	Actor          string    `json:"actor,omitempty"`
	Action         string    `json:"action"`
	Detail         string    `json:"detail,omitempty"`
	Summary        string    `json:"summary,omitempty"`
	IncludedCount  int       `json:"included_count,omitempty"`
	ExcludedCount  int       `json:"excluded_count,omitempty"`
	AddedCount     int       `json:"added_count,omitempty"`
	RemovedCount   int       `json:"removed_count,omitempty"`
	ConflictCount  int       `json:"conflict_count,omitempty"`
	EntryCount     int       `json:"entry_count,omitempty"`
	TargetMode     string    `json:"target_mode,omitempty"`
	EmergencyEmpty bool      `json:"emergency_empty,omitempty"`
}

func (s *Server) handleAGHManagedHistory(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var events []aghManagedHistoryEvent
	var audit []AuditEntry
	for _, entry := range s.store.AuditLog(500) {
		if !strings.HasPrefix(entry.Action, "agh_managed.") {
			continue
		}
		audit = append(audit, entry)
		events = append(events, aghManagedHistoryEvent{
			Time: entry.Time, Kind: "audit", Actor: entry.Actor, Action: entry.Action, Detail: entry.Detail,
		})
	}
	feedHistory := s.deps.AGHManaged.ListFeedHistory()
	for _, rec := range feedHistory {
		events = append(events, aghManagedHistoryEvent{
			Time: rec.Time, Kind: "feed_generation", Action: "feed generation", IncludedCount: rec.IncludedCount,
			ExcludedCount: rec.ExcludedCount, AddedCount: rec.AddedCount, RemovedCount: rec.RemovedCount,
			ConflictCount: rec.ConflictCount, TargetMode: rec.TargetMode, EmergencyEmpty: rec.EmergencyEmpty,
		})
	}
	rollbacks := s.deps.AGHManaged.ListRollbacks()
	for _, rec := range rollbacks {
		events = append(events, aghManagedHistoryEvent{
			Time: rec.Time, Kind: "rollback_candidate", Action: rec.Action, Summary: rec.Summary, EntryCount: len(rec.EntryIDs),
		})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > 200 {
		events = events[:200]
	}
	writeJSON(w, map[string]any{
		"events":       events,
		"audit":        audit,
		"feed_history": feedHistory,
		"rollbacks":    rollbacks,
	})
}

func (s *Server) handleAGHManagedCatalogPatch(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req aghmanaged.CatalogOverride
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	row, err := s.deps.AGHManaged.PatchEntry(r.PathValue("id"), req, sess.username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.catalog.patch", aghManagedCatalogAuditDetail(row.ID, req))
	writeJSON(w, row)
}

func (s *Server) handleAGHManagedCatalogBulkPatch(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		IDs      []string                   `json:"ids"`
		Override aghmanaged.CatalogOverride `json:"override"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	ov := req.Override
	rows, err := s.deps.AGHManaged.BulkPatchEntries(req.IDs, ov, sess.username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.catalog.bulk_patch", aghManagedBulkAuditDetail(len(rows), ov))
	writeJSON(w, map[string]any{"updated": len(rows), "entries": rows})
}

func (s *Server) handleAGHManagedConflictResolve(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Strategy string `json:"strategy,omitempty"`
		aghmanaged.CatalogOverride
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if req.Strategy == "source_priority" {
		rows, err := s.deps.AGHManaged.ResolveConflictByPriority(r.PathValue("id"), sess.username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.store.Audit(sess.username, "agh_managed.conflict.resolve", fmt.Sprintf("id=%s strategy=source_priority updated=%d", r.PathValue("id"), len(rows)))
		writeJSON(w, map[string]any{"updated": len(rows), "entries": rows})
		return
	}
	ov := req.CatalogOverride
	row, err := s.deps.AGHManaged.ResolveConflict(r.PathValue("id"), ov, sess.username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.conflict.resolve", aghManagedCatalogAuditDetail(row.ID, ov))
	writeJSON(w, row)
}

func (s *Server) handleAGHManagedRollbackApply(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	rows, err := s.deps.AGHManaged.Rollback(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.rollback", fmt.Sprintf("rollback_id=%s updated=%d", r.PathValue("id"), len(rows)))
	writeJSON(w, map[string]any{"updated": len(rows), "entries": rows})
}

func (s *Server) handleAGHManagedFeedStatus(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	status := s.deps.AGHManaged.Status(r.Context())
	status.FeedURL = aghManagedFeedURL(r, status.FeedPath)
	writeJSON(w, status)
}

type aghManagedTargetConfigRequest struct {
	TargetMode     string   `json:"target_mode"`
	TargetName     string   `json:"target_name"`
	StaticIPv4     []string `json:"static_ipv4"`
	StaticIPv6     []string `json:"static_ipv6"`
	StaleTargetTTL string   `json:"stale_target_ttl"`
}

func (s *Server) handleAGHManagedTargetConfig(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	cfg := s.deps.AGHManaged.Config()
	status := s.deps.AGHManaged.Status(r.Context())
	status.FeedURL = aghManagedFeedURL(r, status.FeedPath)
	writeJSON(w, map[string]any{
		"target_mode":      cfg.TargetMode,
		"target_name":      cfg.TargetName,
		"static_ipv4":      cfg.StaticIPv4,
		"static_ipv6":      cfg.StaticIPv6,
		"stale_target_ttl": cfg.StaleTargetTTL,
		"status":           status,
	})
}

func (s *Server) handleAGHManagedTargetConfigPut(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req aghManagedTargetConfigRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	cfg, content, err := updateAGHManagedTargetConfigFile(s.deps.ConfigPath, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.WriteFile(s.deps.ConfigPath, []byte(content), 0o600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = os.Chmod(s.deps.ConfigPath, 0o600)
	s.store.Audit(sess.username, "agh_managed.target_config", aghManagedTargetConfigAuditDetail(cfg.AGHManaged))
	status := s.deps.AGHManaged.Status(r.Context())
	status.FeedURL = aghManagedFeedURL(r, status.FeedPath)
	writeJSON(w, map[string]any{
		"status":           "ok",
		"note":             "call /api/reload to apply",
		"target_mode":      cfg.AGHManaged.TargetMode,
		"target_name":      cfg.AGHManaged.TargetName,
		"static_ipv4":      cfg.AGHManaged.StaticIPv4,
		"static_ipv6":      cfg.AGHManaged.StaticIPv6,
		"stale_target_ttl": cfg.AGHManaged.StaleTargetTTL,
		"feed_status":      status,
	})
}

func (s *Server) handleAGHManagedAGHStatus(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	status := s.deps.AGHManaged.Status(r.Context())
	feedURL := aghManagedFeedURL(r, status.FeedPath)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	registration, err := checkAGHFeedRegistration(ctx, s.deps.AGHHTTPClient, s.deps.AGHSyncConfig, feedURL)
	if err != nil {
		code := http.StatusBadGateway
		if isAGHRefreshConfigError(err) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	resp := map[string]any{
		"base_url":       registration.BaseURL,
		"feed_url":       registration.FeedURL,
		"registered":     registration.Registered,
		"enabled":        registration.Enabled,
		"matched_filter": registration.MatchedFilter,
	}

	preview, err := s.deps.AGHManaged.Generate(ctx, true)
	if err != nil {
		resp["message"] = "feed preview unavailable: " + err.Error()
		writeJSON(w, resp)
		return
	}
	domain := firstIncludedManagedDomain(preview)
	if domain == "" {
		resp["message"] = "no included feed item to check"
		writeJSON(w, resp)
		return
	}
	result, err := checkAGHHost(ctx, s.deps.AGHHTTPClient, s.deps.AGHSyncConfig, domain)
	if err != nil {
		code := http.StatusBadGateway
		if isAGHRefreshConfigError(err) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	resp["check_domain"] = domain
	resp["check_result"] = result
	writeJSON(w, resp)
}

func firstIncludedManagedDomain(preview aghmanaged.Preview) string {
	for _, item := range preview.Items {
		if item.Included && item.Domain != "" {
			return item.Domain
		}
	}
	return ""
}

func (s *Server) handleAGHManagedFeedPreview(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	p, err := s.deps.AGHManaged.Generate(r.Context(), true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, p)
}

func (s *Server) handleAGHManagedFeedExport(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	p, err := s.deps.AGHManaged.Generate(r.Context(), false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	name := "mirage-chaff-managed-rewrites-" + time.Now().UTC().Format("20060102T150405Z") + ".txt"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(p.Lines))
}

func (s *Server) handleAGHManagedRefreshTarget(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	status, err := s.deps.AGHManaged.RefreshTarget(r.Context())
	s.store.Audit(sess.username, "agh_managed.refresh_target", mapErr(err))
	writeJSON(w, map[string]any{"status": status, "error": errString(err)})
}

func (s *Server) handleAGHManagedEmergencyEmpty(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if err := s.deps.AGHManaged.SetEmergencyEmpty(req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.Audit(sess.username, "agh_managed.emergency_empty", mapBool(req.Enabled))
	writeJSON(w, map[string]any{"status": "ok", "emergency_empty": req.Enabled})
}

func (s *Server) handleAGHManagedPreset(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Preset string `json:"preset"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if err := s.deps.AGHManaged.SetPreset(req.Preset); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.preset", req.Preset)
	status := s.deps.AGHManaged.Status(r.Context())
	status.FeedURL = aghManagedFeedURL(r, status.FeedPath)
	writeJSON(w, status)
}

func (s *Server) handleAGHManagedRefreshAGH(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Force bool `json:"force"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := refreshAGHFilters(ctx, s.deps.AGHHTTPClient, s.deps.AGHSyncConfig, req.Force)
	if err != nil {
		detail := fmt.Sprintf("force=%s result=%s", mapBool(req.Force), err.Error())
		s.store.Audit(sess.username, "agh_managed.agh_refresh", detail)
		status := http.StatusBadGateway
		if isAGHRefreshConfigError(err) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.store.Audit(sess.username, "agh_managed.agh_refresh", fmt.Sprintf("base_url=%s force=%s result=ok", result.BaseURL, mapBool(result.Force)))
	writeJSON(w, map[string]any{"status": "ok", "force": result.Force, "base_url": result.BaseURL})
}

func isAGHRefreshConfigError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "base_url required") || strings.Contains(msg, "credentials required") || strings.Contains(msg, "env file")
}

func updateAGHManagedTargetConfigFile(path string, req aghManagedTargetConfigRequest) (config.Config, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Config{}, "", fmt.Errorf("config file required for target settings: %w", err)
		}
		return config.Config{}, "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg.AGHManaged.TargetMode = strings.TrimSpace(req.TargetMode)
	cfg.AGHManaged.TargetName = strings.TrimSpace(req.TargetName)
	cfg.AGHManaged.StaticIPv4 = cleanStringList(req.StaticIPv4)
	cfg.AGHManaged.StaticIPv6 = cleanStringList(req.StaticIPv6)
	cfg.AGHManaged.StaleTargetTTL = strings.TrimSpace(req.StaleTargetTTL)
	if err := cfg.Check(); err != nil {
		return config.Config{}, "", fmt.Errorf("invalid config: %w", err)
	}
	content := patchAGHManagedTargetConfig(string(raw), cfg.AGHManaged)
	checkPath := path + ".check"
	if err := os.WriteFile(checkPath, []byte(content), 0o600); err != nil {
		return config.Config{}, "", err
	}
	checked, checkErr := config.Load(checkPath)
	removeErr := os.Remove(checkPath)
	if checkErr == nil {
		checkErr = checked.Check()
	}
	if checkErr != nil {
		return config.Config{}, "", fmt.Errorf("invalid generated config: %w", checkErr)
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return config.Config{}, "", removeErr
	}
	return cfg, content, nil
}

func patchAGHManagedTargetConfig(raw string, cfg config.AGHManagedConfig) string {
	lines := strings.Split(raw, "\n")
	hadTrailingNewline := strings.HasSuffix(raw, "\n")
	start, end := aghManagedConfigSection(lines)
	targetLines := []string{
		`target_mode = ` + tomlString(stringDefault(cfg.TargetMode, "resolved_ip")),
		`target_name = ` + tomlString(cfg.TargetName),
		`static_ipv4 = ` + tomlStringArray(cfg.StaticIPv4),
		`static_ipv6 = ` + tomlStringArray(cfg.StaticIPv6),
		`stale_target_ttl = ` + tomlString(stringDefault(cfg.StaleTargetTTL, "24h")),
	}
	if start == -1 {
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		lines = append(lines, "[agh_managed_rewrites]")
		lines = append(lines, targetLines...)
		out := strings.Join(lines, "\n")
		if hadTrailingNewline || !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		return out
	}
	updates := map[string]string{}
	for _, line := range targetLines {
		key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		updates[key] = line
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(lines)+len(targetLines))
	out = append(out, lines[:start+1]...)
	for _, line := range lines[start+1 : end] {
		key := tomlKey(line)
		if next, ok := updates[key]; ok {
			out = append(out, preserveIndent(line)+next)
			seen[key] = true
			continue
		}
		out = append(out, line)
	}
	for _, line := range targetLines {
		key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if !seen[key] {
			out = append(out, line)
		}
	}
	out = append(out, lines[end:]...)
	result := strings.Join(out, "\n")
	if hadTrailingNewline && !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return result
}

func aghManagedConfigSection(lines []string) (int, int) {
	start := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[agh_managed_rewrites]" {
			start = i
			continue
		}
		if start != -1 && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			return start, i
		}
	}
	if start == -1 {
		return -1, -1
	}
	return start, len(lines)
}

func tomlKey(line string) string {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "=") {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(trimmed, "=", 2)[0])
}

func preserveIndent(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

func tomlString(v string) string {
	return strconv.Quote(v)
}

func tomlStringArray(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, tomlString(v))
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func aghManagedTargetConfigAuditDetail(cfg config.AGHManagedConfig) string {
	return fmt.Sprintf(
		"target_mode=%s target_name=%s static_ipv4=%s static_ipv6=%s stale_target_ttl=%s",
		stringDefault(cfg.TargetMode, "resolved_ip"), cfg.TargetName, strings.Join(cfg.StaticIPv4, ","), strings.Join(cfg.StaticIPv6, ","), stringDefault(cfg.StaleTargetTTL, "24h"),
	)
}

func stringDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func mapBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func aghManagedFeedURL(r *http.Request, feedPath string) string {
	if feedPath == "" {
		feedPath = "/agh/managed-rewrites.txt"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	}
	host := r.Host
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = strings.Split(forwarded, ",")[0]
	}
	if host == "" {
		return feedPath
	}
	if !strings.HasPrefix(feedPath, "/") {
		feedPath = "/" + feedPath
	}
	return scheme + "://" + host + feedPath
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func mapErr(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func aghManagedSourceAuditDetail(src aghmanaged.Source) string {
	return fmt.Sprintf(
		"id=%s type=%s enabled=%s pending=%s entries=%d unsupported=%d allow_exceptions=%d priority=%d stale_feed_policy=%s",
		src.ID,
		src.Type,
		mapBool(src.Enabled),
		mapBool(src.PendingReview),
		src.Entries,
		src.Unsupported,
		src.AllowExceptions,
		src.Priority,
		src.StaleFeedPolicy,
	)
}

func aghManagedSourceSyncAuditDetail(src aghmanaged.Source) string {
	return fmt.Sprintf(
		"id=%s entries=%d added=%d removed=%d changed=%d pending=%s unsupported=%d allow_exceptions=%d",
		src.ID,
		src.Entries,
		src.Added,
		src.Removed,
		src.Changed,
		mapBool(src.PendingReview),
		src.Unsupported,
		src.AllowExceptions,
	)
}

func aghManagedCatalogAuditDetail(id string, ov aghmanaged.CatalogOverride) string {
	fields := aghManagedOverrideFields(ov)
	if len(fields) == 0 {
		return "id=" + id
	}
	return fmt.Sprintf("id=%s fields=%s", id, strings.Join(fields, ","))
}

func aghManagedBulkAuditDetail(updated int, ov aghmanaged.CatalogOverride) string {
	fields := aghManagedOverrideFields(ov)
	if len(fields) == 0 {
		return fmt.Sprintf("updated=%d", updated)
	}
	return fmt.Sprintf("updated=%d fields=%s", updated, strings.Join(fields, ","))
}

func aghManagedOverrideFields(ov aghmanaged.CatalogOverride) []string {
	var fields []string
	if ov.Category != "" {
		fields = append(fields, "category")
	}
	if ov.ResourceType != "" {
		fields = append(fields, "resource_type")
	}
	if ov.Risk != "" {
		fields = append(fields, "risk")
	}
	if ov.Confidence != "" {
		fields = append(fields, "confidence")
	}
	if ov.ReviewStatus != "" {
		fields = append(fields, "review_status")
	}
	if ov.Verified != nil {
		fields = append(fields, "verified")
	}
	if ov.ExpectedCatalog != "" {
		fields = append(fields, "expected_catalog")
	}
	if ov.Action != "" {
		fields = append(fields, "action")
	}
	if ov.RewriteEnabled != nil {
		fields = append(fields, "rewrite_enabled")
	}
	if ov.RewriteReason != "" {
		fields = append(fields, "rewrite_reason")
	}
	if ov.Notes != "" {
		fields = append(fields, "notes")
	}
	return fields
}
