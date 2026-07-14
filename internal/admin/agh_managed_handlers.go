package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/aghmanaged"
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

func (s *Server) handleAGHManagedCatalogPatch(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.deps.AGHManaged == nil {
		http.Error(w, "managed rewrites unavailable", http.StatusServiceUnavailable)
		return
	}
	var req aghmanaged.CatalogOverride
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	row, err := s.deps.AGHManaged.PatchEntry(r.PathValue("id"), req)
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
	ov := aghmanaged.CatalogOverride{
		Category:       req.Override.Category,
		ReviewStatus:   req.Override.ReviewStatus,
		RewriteEnabled: req.Override.RewriteEnabled,
		RewriteReason:  req.Override.RewriteReason,
	}
	rows, err := s.deps.AGHManaged.BulkPatchEntries(req.IDs, ov)
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
	var req aghmanaged.CatalogOverride
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	row, err := s.deps.AGHManaged.ResolveConflict(r.PathValue("id"), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Audit(sess.username, "agh_managed.conflict.resolve", aghManagedCatalogAuditDetail(row.ID, req))
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
	writeJSON(w, s.deps.AGHManaged.Status(r.Context()))
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

func mapBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
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
		"id=%s type=%s enabled=%s pending=%s entries=%d unsupported=%d allow_exceptions=%d",
		src.ID,
		src.Type,
		mapBool(src.Enabled),
		mapBool(src.PendingReview),
		src.Entries,
		src.Unsupported,
		src.AllowExceptions,
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
