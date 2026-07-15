// Package aghmanaged owns mirage-chaff managed AdGuard Home DNS rewrite feeds.
package aghmanaged

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/rulecatalog"
)

const (
	SourceFilterURL        = "filter_url"
	SourceManual           = "manual"
	SourceAGHCustomRules   = "agh_custom_rules"
	SourceAGHQueryLogCNAME = "agh_query_log_cname"

	StaleFeedPolicyExclude = "exclude"
	StaleFeedPolicyKeep    = "keep"
)

// Resolver resolves the managed rewrite target name.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// Source describes one continuously imported source.
type Source struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"`
	Name             string    `json:"name"`
	URL              string    `json:"url,omitempty"`
	Content          string    `json:"content,omitempty"`
	Enabled          bool      `json:"enabled"`
	SyncInterval     string    `json:"sync_interval,omitempty"`
	NextSync         time.Time `json:"next_sync,omitempty"`
	LastSyncStarted  time.Time `json:"last_sync_started,omitempty"`
	LastSuccess      time.Time `json:"last_success,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	LastDurationMS   int64     `json:"last_duration_ms,omitempty"`
	ConsecutiveFails int       `json:"consecutive_failures,omitempty"`
	Entries          int       `json:"entries"`
	Added            int       `json:"added"`
	Removed          int       `json:"removed"`
	Changed          int       `json:"changed"`
	Unsupported      int       `json:"unsupported"`
	AllowExceptions  int       `json:"allow_exceptions"`
	PendingReview    bool      `json:"pending_review,omitempty"`
	Priority         int       `json:"priority"`
	StaleFeedPolicy  string    `json:"stale_feed_policy,omitempty"`
	Health           string    `json:"health,omitempty"`
}

// FeedStatus summarizes generated feed state for the admin UI.
type FeedStatus struct {
	Enabled         bool                   `json:"enabled"`
	FeedPath        string                 `json:"feed_path"`
	FeedURL         string                 `json:"feed_url,omitempty"`
	TargetMode      string                 `json:"target_mode"`
	TargetName      string                 `json:"target_name"`
	ResolvedIPs     []string               `json:"resolved_ips,omitempty"`
	StaticIPs       []string               `json:"static_ips,omitempty"`
	LastResolve     time.Time              `json:"last_resolve,omitempty"`
	LastResolveErr  string                 `json:"last_resolve_error,omitempty"`
	TargetCacheUsed bool                   `json:"target_cache_used,omitempty"`
	ItemCount       int                    `json:"item_count"`
	ExcludedCount   int                    `json:"excluded_count"`
	ConflictCount   int                    `json:"conflict_count"`
	EmergencyEmpty  bool                   `json:"emergency_empty"`
	Sources         int                    `json:"sources"`
	PendingSources  int                    `json:"pending_sources"`
	StaleSources    int                    `json:"stale_sources"`
	LastSourceSync  time.Time              `json:"last_source_sync,omitempty"`
	LastGenerated   time.Time              `json:"last_generated,omitempty"`
	History         []FeedGenerationRecord `json:"history,omitempty"`
}

// FeedGenerationRecord captures one served feed generation summary.
type FeedGenerationRecord struct {
	Time           time.Time `json:"time"`
	IncludedCount  int       `json:"included_count"`
	ExcludedCount  int       `json:"excluded_count"`
	AddedCount     int       `json:"added_count"`
	RemovedCount   int       `json:"removed_count"`
	ConflictCount  int       `json:"conflict_count"`
	TargetMode     string    `json:"target_mode"`
	EmergencyEmpty bool      `json:"emergency_empty"`
}

// Preview is a generated feed plus status.
type Preview struct {
	Status  FeedStatus   `json:"status"`
	Items   []FeedItem   `json:"items"`
	Lines   string       `json:"lines"`
	Sources []Source     `json:"sources,omitempty"`
	Entries []CatalogRow `json:"entries,omitempty"`
}

// FeedItem is one included/excluded managed rewrite candidate.
type FeedItem struct {
	Domain         string   `json:"domain"`
	EntryID        string   `json:"entry_id"`
	SourceIDs      []string `json:"source_ids,omitempty"`
	Category       string   `json:"category,omitempty"`
	ResourceType   string   `json:"resource_type,omitempty"`
	ReviewStatus   string   `json:"review_status,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	RewriteEnabled bool     `json:"rewrite_enabled"`
	Included       bool     `json:"included"`
	Reason         string   `json:"reason"`
	Lines          []string `json:"lines,omitempty"`
}

// CatalogRow is an editable catalog row exposed to the admin UI.
type CatalogRow struct {
	rulecatalog.Entry
	SourceIDs          []string  `json:"source_ids,omitempty"`
	SourcePriority     int       `json:"source_priority"`
	Action             string    `json:"action,omitempty"`
	Notes              string    `json:"notes,omitempty"`
	RewriteEnabled     bool      `json:"rewrite_enabled"`
	RewriteReason      string    `json:"rewrite_reason,omitempty"`
	LastChangedBy      string    `json:"last_changed_by,omitempty"`
	LastFeedIncludedAt time.Time `json:"last_feed_included_at,omitempty"`
}

// Conflict is a grouped domain/path disagreement that blocks feed emission.
type Conflict struct {
	ID             string       `json:"id"`
	Domain         string       `json:"domain"`
	Path           string       `json:"path,omitempty"`
	SourceIDs      []string     `json:"source_ids,omitempty"`
	Reasons        []string     `json:"reasons"`
	Entries        []CatalogRow `json:"entries"`
	ResolutionHint string       `json:"resolution_hint,omitempty"`
}

// PendingDiff describes a pending large-change review for one source.
type PendingDiff struct {
	Source  Source              `json:"source"`
	Added   []rulecatalog.Entry `json:"added"`
	Removed []rulecatalog.Entry `json:"removed"`
	Changed []rulecatalog.Entry `json:"changed"`
}

// RollbackRecord captures one reversible catalog override change.
type RollbackRecord struct {
	ID           string                     `json:"id"`
	Time         time.Time                  `json:"time"`
	Action       string                     `json:"action"`
	EntryIDs     []string                   `json:"entry_ids"`
	Before       map[string]CatalogOverride `json:"before,omitempty"`
	BeforeExists map[string]bool            `json:"before_exists,omitempty"`
	After        map[string]CatalogOverride `json:"after,omitempty"`
	Summary      string                     `json:"summary,omitempty"`
}

type state struct {
	Sources            []Source                       `json:"sources"`
	Entries            []rulecatalog.Entry            `json:"entries"`
	Pending            map[string][]rulecatalog.Entry `json:"pending,omitempty"`
	Overrides          map[string]CatalogOverride     `json:"overrides,omitempty"`
	EmergencyEmpty     *bool                          `json:"emergency_empty,omitempty"`
	Rollbacks          []RollbackRecord               `json:"rollbacks,omitempty"`
	FeedIncludedAtByID map[string]time.Time           `json:"feed_included_at_by_id,omitempty"`
	FeedHistory        []FeedGenerationRecord         `json:"feed_history,omitempty"`
	FeedSnapshotIDs    []string                       `json:"feed_snapshot_entry_ids,omitempty"`
}

// CatalogOverride holds admin-owned state over imported entries.
type CatalogOverride struct {
	Category        string `json:"category,omitempty"`
	ResourceType    string `json:"resource_type,omitempty"`
	Risk            string `json:"risk,omitempty"`
	Confidence      string `json:"confidence,omitempty"`
	ReviewStatus    string `json:"review_status,omitempty"`
	Verified        *bool  `json:"verified,omitempty"`
	ExpectedCatalog string `json:"expected_catalog,omitempty"`
	Action          string `json:"action,omitempty"`
	RewriteEnabled  *bool  `json:"rewrite_enabled,omitempty"`
	RewriteReason   string `json:"rewrite_reason,omitempty"`
	Notes           string `json:"notes,omitempty"`
	LastChangedBy   string `json:"last_changed_by,omitempty"`
}

// Manager stores sources, imports entries, and generates AGH rewrite feeds.
type Manager struct {
	path     string
	cfg      config.AGHManagedConfig
	resolver Resolver
	client   *http.Client

	mu           sync.RWMutex
	sources      map[string]Source
	entries      map[string]rulecatalog.Entry
	pending      map[string][]rulecatalog.Entry
	overrides    map[string]CatalogOverride
	rollbacks    []RollbackRecord
	feedSeen     map[string]time.Time
	feedSnapshot map[string]bool
	feedHistory  []FeedGenerationRecord

	targetIPs      []net.IP
	lastResolve    time.Time
	lastResolveErr string
	lastGenerated  time.Time
}

// Open loads or creates a manager store.
func Open(path string, cfg config.AGHManagedConfig, res Resolver) (*Manager, error) {
	m := &Manager{
		path:         path,
		cfg:          cfg,
		resolver:     res,
		client:       &http.Client{Timeout: durationOr(cfg.Scheduler.SyncTimeout, 30*time.Second)},
		sources:      map[string]Source{},
		entries:      map[string]rulecatalog.Entry{},
		pending:      map[string][]rulecatalog.Entry{},
		overrides:    map[string]CatalogOverride{},
		feedSeen:     map[string]time.Time{},
		feedSnapshot: map[string]bool{},
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		var st state
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("parse managed rewrites: %w", err)
		}
		for _, src := range st.Sources {
			m.sources[src.ID] = src
		}
		for _, e := range st.Entries {
			m.entries[e.ID] = e
		}
		if st.Pending != nil {
			m.pending = st.Pending
		}
		if st.Overrides != nil {
			m.overrides = st.Overrides
		}
		if st.EmergencyEmpty != nil {
			m.cfg.EmergencyEmpty = *st.EmergencyEmpty
		}
		if st.Rollbacks != nil {
			m.rollbacks = st.Rollbacks
		}
		if st.FeedIncludedAtByID != nil {
			m.feedSeen = st.FeedIncludedAtByID
		}
		if st.FeedHistory != nil {
			m.feedHistory = st.FeedHistory
		}
		for _, id := range st.FeedSnapshotIDs {
			m.feedSnapshot[id] = true
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func (m *Manager) SetConfig(cfg config.AGHManagedConfig) {
	m.mu.Lock()
	emergency := m.cfg.EmergencyEmpty
	m.cfg = cfg
	m.cfg.EmergencyEmpty = emergency
	m.client.Timeout = durationOr(cfg.Scheduler.SyncTimeout, 30*time.Second)
	m.mu.Unlock()
}

func (m *Manager) Config() config.AGHManagedConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) ListSources() []Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Source, 0, len(m.sources))
	for _, src := range m.sources {
		src.Health = m.sourceHealthLocked(src)
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Manager) sourceHealthLocked(src Source) string {
	switch {
	case !src.Enabled:
		return "paused"
	case src.PendingReview:
		return "pending"
	case isRemoteSource(src.Type) && isStaleSource(src, staleSourceDuration(m.cfg.Scheduler.StaleSourceTTL)):
		return "stale"
	case src.LastError != "":
		return "failing"
	case src.LastSuccess.IsZero():
		return "never synced"
	default:
		return "healthy"
	}
}

func (m *Manager) UpsertSource(src Source) (Source, error) {
	if src.Type == "" {
		src.Type = SourceFilterURL
	}
	if src.Name == "" {
		src.Name = src.URL
	}
	if src.ID == "" {
		src.ID = sourceID(src)
	}
	if src.SyncInterval == "" {
		src.SyncInterval = m.Config().Scheduler.DefaultSyncInterval
	}
	if src.StaleFeedPolicy == "" {
		src.StaleFeedPolicy = StaleFeedPolicyExclude
	}
	if !validSourceType(src.Type) {
		return Source{}, fmt.Errorf("invalid source type %q", src.Type)
	}
	if !validStaleFeedPolicy(src.StaleFeedPolicy) {
		return Source{}, fmt.Errorf("invalid stale feed policy %q", src.StaleFeedPolicy)
	}
	if src.Type == SourceFilterURL && src.URL == "" {
		return Source{}, fmt.Errorf("url required")
	}
	if (src.Type == SourceAGHCustomRules || src.Type == SourceAGHQueryLogCNAME) && src.URL == "" {
		return Source{}, fmt.Errorf("agh base url required")
	}
	if src.Type == SourceManual && src.Content == "" {
		return Source{}, fmt.Errorf("content required")
	}
	src.Health = ""
	m.mu.Lock()
	if old, ok := m.sources[src.ID]; ok {
		src.LastSyncStarted = old.LastSyncStarted
		src.LastSuccess = old.LastSuccess
		src.LastError = old.LastError
		src.LastDurationMS = old.LastDurationMS
		src.ConsecutiveFails = old.ConsecutiveFails
		src.NextSync = old.NextSync
		src.Entries = old.Entries
		src.Added = old.Added
		src.Removed = old.Removed
		src.Changed = old.Changed
		src.Unsupported = old.Unsupported
		src.AllowExceptions = old.AllowExceptions
		src.PendingReview = old.PendingReview
	}
	m.sources[src.ID] = src
	err := m.saveLocked()
	m.mu.Unlock()
	return src, err
}

func (m *Manager) DeleteSource(id string) error {
	m.mu.Lock()
	delete(m.sources, id)
	delete(m.pending, id)
	for eid, e := range m.entries {
		if e.Source.Name == id {
			delete(m.entries, eid)
			delete(m.overrides, eid)
			delete(m.feedSeen, eid)
		}
	}
	err := m.saveLocked()
	m.mu.Unlock()
	return err
}

func (m *Manager) SyncSource(ctx context.Context, id string) (Source, error) {
	m.mu.RLock()
	src, ok := m.sources[id]
	m.mu.RUnlock()
	if !ok {
		return Source{}, os.ErrNotExist
	}
	start := time.Now()
	src.LastSyncStarted = start
	entries, err := m.fetchSource(ctx, src)
	src.LastDurationMS = time.Since(start).Milliseconds()
	if err != nil {
		src.LastError = err.Error()
		src.ConsecutiveFails++
		src.NextSync = nextSync(src.SyncInterval, m.Config().Scheduler.Jitter)
		m.mu.Lock()
		m.sources[id] = src
		_ = m.saveLocked()
		m.mu.Unlock()
		return src, err
	}
	src.LastError = ""
	src.LastSuccess = time.Now()
	src.ConsecutiveFails = 0
	src.NextSync = nextSync(src.SyncInterval, m.Config().Scheduler.Jitter)
	src.Entries = len(entries)
	src.Unsupported, src.AllowExceptions = countImported(entries)

	m.mu.Lock()
	prev := entriesForSource(m.entries, id)
	src.Added, src.Removed, src.Changed = diffEntries(prev, entries)
	src.PendingReview = largeChange(src, m.cfg.Scheduler)
	m.sources[id] = src
	if !src.PendingReview {
		m.applyEntriesLocked(id, entries)
		delete(m.pending, id)
	} else {
		m.pending[id] = entries
	}
	err = m.saveLocked()
	m.mu.Unlock()
	return src, err
}

func (m *Manager) ApproveSource(id string) (Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src, ok := m.sources[id]
	if !ok {
		return Source{}, os.ErrNotExist
	}
	entries, ok := m.pending[id]
	if !ok {
		return Source{}, os.ErrNotExist
	}
	prev := entriesForSource(m.entries, id)
	src.Added, src.Removed, src.Changed = diffEntries(prev, entries)
	src.Entries = len(entries)
	src.Unsupported, src.AllowExceptions = countImported(entries)
	src.PendingReview = false
	m.applyEntriesLocked(id, entries)
	delete(m.pending, id)
	m.sources[id] = src
	if err := m.saveLocked(); err != nil {
		return Source{}, err
	}
	return src, nil
}

func (m *Manager) RejectSource(id string) (Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src, ok := m.sources[id]
	if !ok {
		return Source{}, os.ErrNotExist
	}
	if _, ok := m.pending[id]; !ok {
		return Source{}, os.ErrNotExist
	}
	src.PendingReview = false
	delete(m.pending, id)
	m.sources[id] = src
	if err := m.saveLocked(); err != nil {
		return Source{}, err
	}
	return src, nil
}

func (m *Manager) PendingDiff(id string) (PendingDiff, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src, ok := m.sources[id]
	if !ok {
		return PendingDiff{}, os.ErrNotExist
	}
	pending, ok := m.pending[id]
	if !ok {
		return PendingDiff{}, os.ErrNotExist
	}
	prev := entriesForSource(m.entries, id)
	return pendingDiff(src, prev, pending), nil
}

func (m *Manager) PreviewSource(ctx context.Context, src Source) (Source, []rulecatalog.Entry, error) {
	if src.Type == "" {
		src.Type = SourceFilterURL
	}
	if src.Name == "" {
		src.Name = src.URL
	}
	if src.ID == "" {
		src.ID = sourceID(src)
	}
	start := time.Now()
	entries, err := m.fetchSource(ctx, src)
	src.LastDurationMS = time.Since(start).Milliseconds()
	if err != nil {
		src.LastError = err.Error()
		return src, nil, err
	}
	src.Entries = len(entries)
	src.Unsupported, src.AllowExceptions = countImported(entries)
	return src, entries, nil
}

func (m *Manager) SyncDue(ctx context.Context) {
	cfg := m.Config()
	if !cfg.Scheduler.Enabled {
		return
	}
	now := time.Now()
	var due []string
	for _, src := range m.ListSources() {
		if !src.Enabled {
			continue
		}
		if !src.NextSync.IsZero() && now.Before(src.NextSync) {
			continue
		}
		due = append(due, src.ID)
	}
	if len(due) == 0 {
		return
	}
	maxParallel := cfg.Scheduler.MaxParallelSyncs
	if maxParallel <= 1 {
		for _, id := range due {
			_, _ = m.SyncSource(ctx, id)
		}
		return
	}
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, id := range due {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_, _ = m.SyncSource(ctx, id)
		}()
	}
	wg.Wait()
}

func (m *Manager) CatalogRows() []CatalogRow {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := make([]CatalogRow, 0, len(m.entries))
	for _, e := range m.entries {
		rows = append(rows, m.catalogRowLocked(e))
	}
	sortCatalogRows(rows)
	return rows
}

func (m *Manager) SourceEntries(id string) ([]CatalogRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.sources[id]; !ok {
		return nil, os.ErrNotExist
	}
	rows := make([]CatalogRow, 0)
	for _, e := range m.entries {
		if e.Source.Name != id {
			continue
		}
		rows = append(rows, m.catalogRowLocked(e))
	}
	sortCatalogRows(rows)
	return rows, nil
}

func (m *Manager) catalogRowLocked(e rulecatalog.Entry) CatalogRow {
	e = m.applyOverrideLocked(e)
	return m.catalogRowFromEntryLocked(e, m.overrides[e.ID])
}

func (m *Manager) catalogRowFromEntryLocked(e rulecatalog.Entry, ov CatalogOverride) CatalogRow {
	return CatalogRow{
		Entry:              e,
		SourceIDs:          []string{e.Source.Name},
		SourcePriority:     m.sourcePriorityLocked(e.Source.Name),
		Action:             ov.Action,
		Notes:              ov.Notes,
		RewriteEnabled:     rewriteEnabled(e, ov, m.cfg),
		RewriteReason:      ov.RewriteReason,
		LastChangedBy:      ov.LastChangedBy,
		LastFeedIncludedAt: m.feedSeen[e.ID],
	}
}

func (m *Manager) sourcePriorityLocked(id string) int {
	if src, ok := m.sources[id]; ok {
		return src.Priority
	}
	return 0
}

func (m *Manager) sourcePrioritiesLocked() map[string]int {
	out := make(map[string]int, len(m.sources))
	for id, src := range m.sources {
		out[id] = src.Priority
	}
	return out
}

func sortCatalogRows(rows []CatalogRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Match.Domain != rows[j].Match.Domain {
			return rows[i].Match.Domain < rows[j].Match.Domain
		}
		return rows[i].ID < rows[j].ID
	})
}

func (m *Manager) ListConflicts() []Conflict {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]rulecatalog.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, m.applyOverrideLocked(e))
	}
	return buildConflicts(entries, m.overrides, m.cfg, m.sourcePrioritiesLocked())
}

func (m *Manager) ResolveConflict(id string, override CatalogOverride, changedBy ...string) (CatalogRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]rulecatalog.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, m.applyOverrideLocked(e))
	}
	conflicts := buildConflicts(entries, m.overrides, m.cfg, m.sourcePrioritiesLocked())
	var targetID string
	for _, c := range conflicts {
		if c.ID != id {
			continue
		}
		for _, row := range c.Entries {
			if row.Category != "allow_exception" && row.RewriteEnabled {
				targetID = row.ID
				break
			}
		}
		if targetID == "" && len(c.Entries) > 0 {
			targetID = c.Entries[0].ID
		}
		break
	}
	if targetID == "" {
		return CatalogRow{}, os.ErrNotExist
	}
	e, ok := m.entries[targetID]
	if !ok {
		return CatalogRow{}, os.ErrNotExist
	}
	cur := m.overrides[targetID]
	before, beforeExists := captureOverrides(m.overrides, []string{targetID})
	mergeOverride(&cur, override)
	setLastChangedBy(&cur, changedBy...)
	m.overrides[targetID] = cur
	m.recordRollbackLocked("conflict resolve", []string{targetID}, before, beforeExists, fmt.Sprintf("resolved %s", id))
	if err := m.saveLocked(); err != nil {
		return CatalogRow{}, err
	}
	e = m.applyOverrideLocked(e)
	return m.catalogRowFromEntryLocked(e, cur), nil
}

func (m *Manager) ResolveConflictByPriority(id string, changedBy ...string) ([]CatalogRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]rulecatalog.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, m.applyOverrideLocked(e))
	}
	conflicts := buildConflicts(entries, m.overrides, m.cfg, m.sourcePrioritiesLocked())
	var target *Conflict
	for i := range conflicts {
		if conflicts[i].ID == id {
			target = &conflicts[i]
			break
		}
	}
	if target == nil {
		return nil, os.ErrNotExist
	}
	var winner CatalogRow
	var winnerSet, tied bool
	for _, row := range target.Entries {
		if !conflictParticipant(row) {
			continue
		}
		if !winnerSet || row.SourcePriority > winner.SourcePriority {
			winner = row
			winnerSet = true
			tied = false
			continue
		}
		if row.SourcePriority == winner.SourcePriority {
			tied = true
		}
	}
	if !winnerSet {
		return nil, os.ErrNotExist
	}
	if tied {
		return nil, fmt.Errorf("source priority tie for conflict %s at priority %d; resolve manually", id, winner.SourcePriority)
	}
	ids := make([]string, 0, len(target.Entries)-1)
	for _, row := range target.Entries {
		if row.ID != winner.ID {
			ids = append(ids, row.ID)
		}
	}
	if len(ids) == 0 {
		return nil, os.ErrNotExist
	}
	before, beforeExists := captureOverrides(m.overrides, ids)
	winnerVerified := winner.Verified
	ov := CatalogOverride{
		Category:        winner.Category,
		ResourceType:    winner.ResourceType,
		Risk:            winner.Risk,
		Confidence:      winner.Confidence,
		ReviewStatus:    winner.ReviewStatus,
		Verified:        &winnerVerified,
		ExpectedCatalog: winner.ExpectedCatalog,
		Action:          winner.Action,
	}
	for _, entryID := range ids {
		cur := m.overrides[entryID]
		mergeOverride(&cur, ov)
		setLastChangedBy(&cur, changedBy...)
		m.overrides[entryID] = cur
	}
	source := ""
	if len(winner.SourceIDs) > 0 {
		source = winner.SourceIDs[0]
	}
	m.recordRollbackLocked("conflict source priority resolve", ids, before, beforeExists, fmt.Sprintf("resolved %s with source %s priority %d", id, source, winner.SourcePriority))
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return m.rowsForIDsLocked(ids), nil
}

func (m *Manager) PatchEntry(id string, ov CatalogOverride, changedBy ...string) (CatalogRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok {
		return CatalogRow{}, os.ErrNotExist
	}
	cur := m.overrides[id]
	before, beforeExists := captureOverrides(m.overrides, []string{id})
	mergeOverride(&cur, ov)
	setLastChangedBy(&cur, changedBy...)
	m.overrides[id] = cur
	m.recordRollbackLocked("catalog patch", []string{id}, before, beforeExists, "patched 1 entry")
	if err := m.saveLocked(); err != nil {
		return CatalogRow{}, err
	}
	e = m.applyOverrideLocked(e)
	return m.catalogRowFromEntryLocked(e, cur), nil
}

func (m *Manager) BulkPatchEntries(ids []string, ov CatalogOverride, changedBy ...string) ([]CatalogRow, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("ids required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if _, ok := m.entries[id]; !ok {
			return nil, fmt.Errorf("entry %q not found", id)
		}
	}
	before, beforeExists := captureOverrides(m.overrides, ids)
	for _, id := range ids {
		cur := m.overrides[id]
		mergeOverride(&cur, ov)
		setLastChangedBy(&cur, changedBy...)
		m.overrides[id] = cur
	}
	m.recordRollbackLocked("catalog bulk patch", ids, before, beforeExists, fmt.Sprintf("bulk patched %d entries", len(ids)))
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return m.rowsForIDsLocked(ids), nil
}

func (m *Manager) ListRollbacks() []RollbackRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RollbackRecord, len(m.rollbacks))
	copy(out, m.rollbacks)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

func (m *Manager) Rollback(id string) ([]CatalogRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, rec := range m.rollbacks {
		if rec.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, os.ErrNotExist
	}
	rec := m.rollbacks[idx]
	targets := map[string]bool{}
	for _, entryID := range rec.EntryIDs {
		if _, ok := m.entries[entryID]; !ok {
			return nil, fmt.Errorf("entry %q not found", entryID)
		}
		targets[entryID] = true
	}
	for i := idx + 1; i < len(m.rollbacks); i++ {
		for _, entryID := range m.rollbacks[i].EntryIDs {
			if targets[entryID] {
				return nil, fmt.Errorf("newer rollback candidate overlaps entry %q", entryID)
			}
		}
	}
	for _, entryID := range rec.EntryIDs {
		if rec.BeforeExists[entryID] {
			m.overrides[entryID] = rec.Before[entryID]
		} else {
			delete(m.overrides, entryID)
		}
	}
	m.rollbacks = append(m.rollbacks[:idx], m.rollbacks[idx+1:]...)
	if err := m.saveLocked(); err != nil {
		return nil, err
	}
	return m.rowsForIDsLocked(rec.EntryIDs), nil
}

func (m *Manager) rowsForIDsLocked(ids []string) []CatalogRow {
	rows := make([]CatalogRow, 0, len(ids))
	for _, id := range ids {
		e := m.applyOverrideLocked(m.entries[id])
		cur := m.overrides[id]
		rows = append(rows, m.catalogRowFromEntryLocked(e, cur))
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Match.Domain != rows[j].Match.Domain {
			return rows[i].Match.Domain < rows[j].Match.Domain
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

func (m *Manager) recordRollbackLocked(action string, ids []string, before map[string]CatalogOverride, beforeExists map[string]bool, summary string) {
	ids = uniqueStrings(ids)
	after := make(map[string]CatalogOverride, len(ids))
	for _, id := range ids {
		after[id] = copyOverride(m.overrides[id])
	}
	h := sha1.Sum([]byte(action + "\x00" + strings.Join(ids, "\x00") + "\x00" + time.Now().UTC().Format(time.RFC3339Nano)))
	rec := RollbackRecord{
		ID:           "rb_" + hex.EncodeToString(h[:])[:12],
		Time:         time.Now(),
		Action:       action,
		EntryIDs:     ids,
		Before:       before,
		BeforeExists: beforeExists,
		After:        after,
		Summary:      summary,
	}
	m.rollbacks = append(m.rollbacks, rec)
	if len(m.rollbacks) > 50 {
		m.rollbacks = m.rollbacks[len(m.rollbacks)-50:]
	}
}

func captureOverrides(overrides map[string]CatalogOverride, ids []string) (map[string]CatalogOverride, map[string]bool) {
	ids = uniqueStrings(ids)
	before := make(map[string]CatalogOverride, len(ids))
	beforeExists := make(map[string]bool, len(ids))
	for _, id := range ids {
		ov, ok := overrides[id]
		beforeExists[id] = ok
		before[id] = copyOverride(ov)
	}
	return before, beforeExists
}

func copyOverride(ov CatalogOverride) CatalogOverride {
	if ov.Verified != nil {
		v := *ov.Verified
		ov.Verified = &v
	}
	if ov.RewriteEnabled != nil {
		v := *ov.RewriteEnabled
		ov.RewriteEnabled = &v
	}
	return ov
}

func uniqueStrings(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (m *Manager) SetEmergencyEmpty(on bool) error {
	m.mu.Lock()
	m.cfg.EmergencyEmpty = on
	err := m.saveLocked()
	m.mu.Unlock()
	return err
}

func (m *Manager) RefreshTarget(ctx context.Context) (FeedStatus, error) {
	m.mu.RLock()
	cfg := m.cfg
	cached := append([]net.IP(nil), m.targetIPs...)
	m.mu.RUnlock()
	if cfg.TargetMode != "" && cfg.TargetMode != "resolved_ip" {
		return m.Status(ctx), nil
	}
	ips, err := m.resolveTarget(ctx, cfg, cached)
	m.mu.Lock()
	if err == nil {
		m.targetIPs = append([]net.IP(nil), ips...)
		m.lastResolve = time.Now()
		m.lastResolveErr = ""
	} else {
		m.lastResolveErr = err.Error()
	}
	m.mu.Unlock()
	return m.Status(ctx), err
}

func (m *Manager) Status(ctx context.Context) FeedStatus {
	p, _ := m.generate(ctx, false, false)
	return p.Status
}

func (m *Manager) Generate(ctx context.Context, includeRows bool) (Preview, error) {
	return m.generate(ctx, includeRows, !includeRows)
}

func (m *Manager) generate(ctx context.Context, includeRows bool, recordHistory bool) (Preview, error) {
	m.mu.RLock()
	cfg := m.cfg
	entries := make([]rulecatalog.Entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, m.applyOverrideLocked(e))
	}
	overrides := make(map[string]CatalogOverride, len(m.overrides))
	for k, v := range m.overrides {
		overrides[k] = v
	}
	feedSeen := make(map[string]time.Time, len(m.feedSeen))
	for k, v := range m.feedSeen {
		feedSeen[k] = v
	}
	sources := make([]Source, 0, len(m.sources))
	for _, src := range m.sources {
		sources = append(sources, src)
	}
	cachedIPs := append([]net.IP(nil), m.targetIPs...)
	lastResolve := m.lastResolve
	lastResolveErr := m.lastResolveErr
	history := make([]FeedGenerationRecord, len(m.feedHistory))
	copy(history, m.feedHistory)
	m.mu.RUnlock()

	var ips []net.IP
	var resolveErr error
	targetCacheUsed := false
	if cfg.TargetMode == "" || cfg.TargetMode == "resolved_ip" {
		ips, resolveErr = m.resolveTarget(ctx, cfg, cachedIPs)
		if resolveErr == nil {
			m.mu.Lock()
			m.targetIPs = append([]net.IP(nil), ips...)
			m.lastResolve = time.Now()
			m.lastResolveErr = ""
			lastResolve = m.lastResolve
			lastResolveErr = ""
			m.mu.Unlock()
		} else {
			lastResolveErr = resolveErr.Error()
			staleTargetTTL := durationOr(cfg.StaleTargetTTL, 24*time.Hour)
			if len(cachedIPs) > 0 && !lastResolve.IsZero() && time.Since(lastResolve) <= staleTargetTTL {
				ips = cachedIPs
				targetCacheUsed = true
			}
		}
	}

	var b bytes.Buffer
	now := time.Now()
	status := FeedStatus{
		Enabled: cfg.Enabled, FeedPath: cfg.FeedPath, TargetMode: nonempty(cfg.TargetMode, "resolved_ip"),
		TargetName: cfg.TargetName, ResolvedIPs: ipStrings(ips), StaticIPs: staticIPStrings(cfg), LastResolve: lastResolve,
		LastResolveErr: lastResolveErr, TargetCacheUsed: targetCacheUsed, EmergencyEmpty: cfg.EmergencyEmpty, Sources: len(sources), LastGenerated: now,
		History: feedHistoryNewestFirst(history),
	}
	sourcePriorities := make(map[string]int, len(sources))
	for _, src := range sources {
		sourcePriorities[src.ID] = src.Priority
	}
	conflicts := buildConflicts(entries, overrides, cfg, sourcePriorities)
	conflictKeys := map[string]bool{}
	for _, conflict := range conflicts {
		conflictKeys[domainPathKey(conflict.Domain, conflict.Path)] = true
	}
	status.ConflictCount = len(conflicts)
	fmt.Fprintf(&b, "! mirage-chaff managed rewrites\n! generated_at=%s\n! target_mode=%s target_name=%s\n", now.Format(time.RFC3339), status.TargetMode, cfg.TargetName)
	if targetCacheUsed {
		fmt.Fprintf(&b, "! target_resolution=stale-cache last_success=%s error=%s\n", lastResolve.Format(time.RFC3339), lastResolveErr)
	}
	if cfg.EmergencyEmpty || !cfg.Enabled {
		fmt.Fprintf(&b, "! feed empty: enabled=%v emergency_empty=%v\n", cfg.Enabled, cfg.EmergencyEmpty)
		status.ExcludedCount = len(entries)
		if recordHistory {
			m.mu.Lock()
			err := m.persistGenerationLocked(status, nil, nil, now, false)
			status.History = feedHistoryNewestFirst(m.feedHistory)
			m.mu.Unlock()
			if err != nil {
				return Preview{Status: status, Lines: b.String(), Sources: sources}, err
			}
		}
		return Preview{Status: status, Lines: b.String(), Sources: sources}, nil
	}
	if (cfg.TargetMode == "" || cfg.TargetMode == "resolved_ip") && len(ips) == 0 {
		return Preview{Status: status, Lines: b.String(), Sources: sources}, fmt.Errorf("target resolution failed: %s", lastResolveErr)
	}
	sourceByID := make(map[string]Source, len(sources))
	for _, src := range sources {
		sourceByID[src.ID] = src
		if src.PendingReview {
			status.PendingSources++
		}
		if src.LastSuccess.After(status.LastSourceSync) {
			status.LastSourceSync = src.LastSuccess
		}
	}
	staleSourceTTL := staleSourceDuration(cfg.Scheduler.StaleSourceTTL)
	staleSources := map[string]bool{}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Match.Domain != entries[j].Match.Domain {
			return entries[i].Match.Domain < entries[j].Match.Domain
		}
		return entries[i].ID < entries[j].ID
	})
	var items []FeedItem
	var includedIDs []string
	for _, e := range entries {
		ov := overrides[e.ID]
		item := m.feedItem(e, ov, cfg, ips, conflictKeys[entryKey(e)])
		if staleSourceTTL > 0 {
			if src, ok := sourceByID[e.Source.Name]; ok && isStaleSource(src, staleSourceTTL) {
				staleSources[src.ID] = true
				if staleFeedPolicy(src) == StaleFeedPolicyExclude {
					item.Included = false
					item.Reason = "stale source"
				}
			}
		}
		if item.Included {
			for _, line := range item.Lines {
				fmt.Fprintf(&b, "! entry_id=%s source=%s category=%s confidence=%s\n%s\n", item.EntryID, strings.Join(item.SourceIDs, ","), item.Category, item.Confidence, line)
			}
			feedSeen[item.EntryID] = now
			includedIDs = append(includedIDs, item.EntryID)
			status.ItemCount++
		} else {
			status.ExcludedCount++
		}
		items = append(items, item)
	}
	status.StaleSources = len(staleSources)
	var saveErr error
	m.mu.Lock()
	if recordHistory {
		saveErr = m.persistGenerationLocked(status, feedSeen, includedIDs, now, true)
		status.History = feedHistoryNewestFirst(m.feedHistory)
	} else {
		m.lastGenerated = now
	}
	m.mu.Unlock()
	if saveErr != nil {
		return Preview{Status: status, Items: items, Lines: b.String(), Sources: sources}, saveErr
	}
	p := Preview{Status: status, Items: items, Lines: b.String(), Sources: sources}
	if includeRows {
		p.Entries = m.CatalogRows()
	}
	return p, nil
}

func (m *Manager) ListFeedHistory() []FeedGenerationRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return feedHistoryNewestFirst(m.feedHistory)
}

func (m *Manager) persistGenerationLocked(status FeedStatus, feedSeen map[string]time.Time, includedIDs []string, generatedAt time.Time, updateFeedSeen bool) error {
	m.lastGenerated = generatedAt
	if updateFeedSeen {
		m.feedSeen = feedSeen
	}
	added, removed := feedSnapshotDelta(m.feedSnapshot, includedIDs)
	m.feedSnapshot = feedSnapshotFromIDs(includedIDs)
	m.feedHistory = append(m.feedHistory, FeedGenerationRecord{
		Time:           generatedAt,
		IncludedCount:  status.ItemCount,
		ExcludedCount:  status.ExcludedCount,
		AddedCount:     added,
		RemovedCount:   removed,
		ConflictCount:  status.ConflictCount,
		TargetMode:     status.TargetMode,
		EmergencyEmpty: status.EmergencyEmpty,
	})
	if len(m.feedHistory) > 50 {
		m.feedHistory = m.feedHistory[len(m.feedHistory)-50:]
	}
	return m.saveLocked()
}

func feedSnapshotDelta(prev map[string]bool, nextIDs []string) (added, removed int) {
	next := feedSnapshotFromIDs(nextIDs)
	for id := range next {
		if !prev[id] {
			added++
		}
	}
	for id := range prev {
		if !next[id] {
			removed++
		}
	}
	return added, removed
}

func feedSnapshotFromIDs(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			out[id] = true
		}
	}
	return out
}

func feedHistoryNewestFirst(history []FeedGenerationRecord) []FeedGenerationRecord {
	out := make([]FeedGenerationRecord, len(history))
	copy(out, history)
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

func (m *Manager) fetchSource(ctx context.Context, src Source) ([]rulecatalog.Entry, error) {
	var content string
	switch src.Type {
	case SourceManual:
		content = src.Content
	case SourceFilterURL:
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("fetch status %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		content = string(b)
	case SourceAGHCustomRules:
		entries, _, err := rulecatalog.Build(rulecatalog.SyncConfig{
			Enabled:         true,
			BaseURL:         src.URL,
			SyncCustomRules: true,
			SyncAllowDeny:   true,
			Client:          m.client,
		})
		return entries, err
	case SourceAGHQueryLogCNAME:
		entries, _, err := rulecatalog.Build(rulecatalog.SyncConfig{
			Enabled:          true,
			BaseURL:          src.URL,
			SyncQueryLog:     true,
			CNAMEEnabled:     true,
			CNAMEUseQueryLog: true,
			Client:           m.client,
		})
		return entries, err
	default:
		return nil, fmt.Errorf("unsupported source type %q", src.Type)
	}
	entries, err := rulecatalog.ParseRules(strings.NewReader(content), rulecatalog.Source{Type: src.Type, Name: src.ID, URL: src.URL})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (m *Manager) resolveTarget(ctx context.Context, cfg config.AGHManagedConfig, cached []net.IP) ([]net.IP, error) {
	if cfg.TargetName == "" {
		return nil, fmt.Errorf("target_name required")
	}
	if m.resolver == nil {
		return cached, fmt.Errorf("resolver unavailable")
	}
	return m.resolver.LookupIP(ctx, cfg.TargetName)
}

func (m *Manager) feedItem(e rulecatalog.Entry, ov CatalogOverride, cfg config.AGHManagedConfig, ips []net.IP, conflict bool) FeedItem {
	item := FeedItem{
		Domain: e.Match.Domain, EntryID: e.ID, SourceIDs: []string{e.Source.Name}, Category: e.Category,
		ResourceType: e.ResourceType, ReviewStatus: e.ReviewStatus, Confidence: e.Confidence,
		RewriteEnabled: rewriteEnabled(e, ov, cfg),
	}
	if e.Match.Domain == "" {
		item.Reason = "empty domain"
		return item
	}
	if e.Unsupported || e.Layer == rulecatalog.LayerDOM {
		item.Reason = "unsupported layer"
		return item
	}
	if e.Layer != "" && e.Layer != rulecatalog.LayerDNS {
		item.Reason = "http layer"
		return item
	}
	if e.Match.Path != "" {
		item.Reason = "path scoped rule"
		return item
	}
	if e.Category == "allow_exception" {
		item.Reason = "allow exception"
		return item
	}
	if conflict {
		item.Reason = "conflict unresolved"
		return item
	}
	if e.ReviewStatus == rulecatalog.ReviewRejected || e.ReviewStatus == rulecatalog.ReviewDisabled {
		item.Reason = "rejected or disabled"
		return item
	}
	if !item.RewriteEnabled {
		item.Reason = "disabled by preset or user"
		return item
	}
	lines, err := rewriteLines(e.Match.Domain, cfg, ips)
	if err != nil {
		item.Reason = err.Error()
		return item
	}
	item.Included = true
	item.Reason = "included"
	item.Lines = lines
	return item
}

func rewriteLines(domain string, cfg config.AGHManagedConfig, ips []net.IP) ([]string, error) {
	mode := nonempty(cfg.TargetMode, "resolved_ip")
	switch mode {
	case "cname":
		if cfg.TargetName == "" {
			return nil, fmt.Errorf("target_name required")
		}
		return []string{fmt.Sprintf("||%s^$dnsrewrite=NOERROR;CNAME;%s", domain, cfg.TargetName)}, nil
	case "static_ip":
		var lines []string
		for _, raw := range cfg.StaticIPv4 {
			if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
				lines = append(lines, fmt.Sprintf("||%s^$dnsrewrite=NOERROR;A;%s", domain, ip.String()))
			}
		}
		for _, raw := range cfg.StaticIPv6 {
			if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
				lines = append(lines, fmt.Sprintf("||%s^$dnsrewrite=NOERROR;AAAA;%s", domain, ip.String()))
			}
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no static IPs")
		}
		return lines, nil
	default:
		var lines []string
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				lines = append(lines, fmt.Sprintf("||%s^$dnsrewrite=NOERROR;A;%s", domain, ip4.String()))
			} else {
				lines = append(lines, fmt.Sprintf("||%s^$dnsrewrite=NOERROR;AAAA;%s", domain, ip.String()))
			}
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("target resolution failed")
		}
		return lines, nil
	}
}

func (m *Manager) applyOverrideLocked(e rulecatalog.Entry) rulecatalog.Entry {
	ov := m.overrides[e.ID]
	if ov.Category != "" {
		e.Category = ov.Category
	}
	if ov.ResourceType != "" {
		e.ResourceType = ov.ResourceType
	}
	if ov.Risk != "" {
		e.Risk = ov.Risk
	}
	if ov.Confidence != "" {
		e.Confidence = ov.Confidence
	}
	if ov.ReviewStatus != "" {
		e.ReviewStatus = ov.ReviewStatus
	}
	if ov.Verified != nil {
		e.Verified = *ov.Verified
	}
	if ov.ExpectedCatalog != "" {
		e.ExpectedCatalog = ov.ExpectedCatalog
	}
	return e
}

func (m *Manager) saveLocked() error {
	emergency := m.cfg.EmergencyEmpty
	st := state{Overrides: m.overrides, EmergencyEmpty: &emergency}
	if len(m.pending) > 0 {
		st.Pending = m.pending
	}
	if len(m.rollbacks) > 0 {
		st.Rollbacks = m.rollbacks
	}
	for _, src := range m.sources {
		st.Sources = append(st.Sources, src)
	}
	for _, e := range m.entries {
		st.Entries = append(st.Entries, e)
	}
	if len(m.feedSeen) > 0 {
		st.FeedIncludedAtByID = m.feedSeen
	}
	if len(m.feedHistory) > 0 {
		st.FeedHistory = m.feedHistory
	}
	if len(m.feedSnapshot) > 0 {
		st.FeedSnapshotIDs = sortedKeys(m.feedSnapshot)
	}
	sort.Slice(st.Sources, func(i, j int) bool { return st.Sources[i].ID < st.Sources[j].ID })
	sort.Slice(st.Entries, func(i, j int) bool { return st.Entries[i].ID < st.Entries[j].ID })
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func (m *Manager) applyEntriesLocked(sourceID string, entries []rulecatalog.Entry) {
	for eid, e := range m.entries {
		if e.Source.Name == sourceID {
			delete(m.entries, eid)
			delete(m.feedSeen, eid)
		}
	}
	for _, e := range entries {
		e.Source.Name = sourceID
		m.entries[e.ID] = e
	}
}

func sourceID(src Source) string {
	material := src.Type + "\x00" + src.Name + "\x00" + src.URL
	if src.Type == SourceManual {
		material = src.Type + "\x00" + src.Name + "\x00" + src.Content
	}
	h := sha1.Sum([]byte(material))
	return "src_" + hex.EncodeToString(h[:])[:12]
}

func entriesForSource(entries map[string]rulecatalog.Entry, sourceID string) []rulecatalog.Entry {
	var out []rulecatalog.Entry
	for _, e := range entries {
		if e.Source.Name == sourceID {
			out = append(out, e)
		}
	}
	return out
}

func diffEntries(prev, next []rulecatalog.Entry) (added, removed, changed int) {
	p := map[string]rulecatalog.Entry{}
	n := map[string]rulecatalog.Entry{}
	for _, e := range prev {
		p[e.ID] = e
	}
	for _, e := range next {
		n[e.ID] = e
		if old, ok := p[e.ID]; !ok {
			added++
		} else if old.OriginalRule != e.OriginalRule || old.Category != e.Category || old.ResourceType != e.ResourceType {
			changed++
		}
	}
	for id := range p {
		if _, ok := n[id]; !ok {
			removed++
		}
	}
	return
}

func pendingDiff(src Source, prev, next []rulecatalog.Entry) PendingDiff {
	p := map[string]rulecatalog.Entry{}
	n := map[string]rulecatalog.Entry{}
	for _, e := range prev {
		p[e.ID] = e
	}
	for _, e := range next {
		n[e.ID] = e
	}
	out := PendingDiff{Source: src}
	for _, e := range next {
		if old, ok := p[e.ID]; !ok {
			out.Added = append(out.Added, e)
		} else if old.OriginalRule != e.OriginalRule || old.Category != e.Category || old.ResourceType != e.ResourceType {
			out.Changed = append(out.Changed, e)
		}
	}
	for _, e := range prev {
		if _, ok := n[e.ID]; !ok {
			out.Removed = append(out.Removed, e)
		}
	}
	sortEntries(out.Added)
	sortEntries(out.Removed)
	sortEntries(out.Changed)
	return out
}

func sortEntries(entries []rulecatalog.Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Match.Domain != entries[j].Match.Domain {
			return entries[i].Match.Domain < entries[j].Match.Domain
		}
		if entries[i].Match.Path != entries[j].Match.Path {
			return entries[i].Match.Path < entries[j].Match.Path
		}
		return entries[i].ID < entries[j].ID
	})
}

func buildConflicts(entries []rulecatalog.Entry, overrides map[string]CatalogOverride, cfg config.AGHManagedConfig, sourcePriorities map[string]int) []Conflict {
	grouped := map[string][]CatalogRow{}
	for _, e := range entries {
		if e.Match.Domain == "" {
			continue
		}
		ov := overrides[e.ID]
		row := CatalogRow{
			Entry:          e,
			SourceIDs:      []string{e.Source.Name},
			SourcePriority: sourcePriorities[e.Source.Name],
			Action:         ov.Action,
			Notes:          ov.Notes,
			RewriteEnabled: rewriteEnabled(e, ov, cfg),
			RewriteReason:  ov.RewriteReason,
			LastChangedBy:  ov.LastChangedBy,
		}
		grouped[entryKey(e)] = append(grouped[entryKey(e)], row)
	}
	var out []Conflict
	for key, rows := range grouped {
		if len(rows) < 2 {
			continue
		}
		var participants []CatalogRow
		for _, row := range rows {
			if conflictParticipant(row) {
				participants = append(participants, row)
			}
		}
		if len(participants) < 2 {
			continue
		}
		categories := map[string]bool{}
		reviews := map[string]bool{}
		sourceIDs := map[string]bool{}
		var hasAllow, hasRewrite bool
		for _, row := range participants {
			categories[row.Category] = true
			reviews[row.ReviewStatus] = true
			if row.Category == "allow_exception" {
				hasAllow = true
			} else if row.RewriteEnabled {
				hasRewrite = true
			}
			for _, id := range row.SourceIDs {
				sourceIDs[id] = true
			}
		}
		var reasons []string
		if len(categories) > 1 {
			reasons = append(reasons, "category mismatch")
		}
		if len(reviews) > 1 {
			reasons = append(reasons, "review_status mismatch")
		}
		if hasAllow && hasRewrite {
			reasons = append(reasons, "allow_exception conflicts with rewrite candidate")
		}
		if len(reasons) == 0 {
			continue
		}
		domain, path := splitEntryKey(key)
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		out = append(out, Conflict{
			ID:             conflictID(domain, path),
			Domain:         domain,
			Path:           path,
			SourceIDs:      sortedKeys(sourceIDs),
			Reasons:        reasons,
			Entries:        rows,
			ResolutionHint: resolutionHint(reasons),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func conflictParticipant(row CatalogRow) bool {
	return row.Category == "allow_exception" || row.RewriteEnabled
}

func entryKey(e rulecatalog.Entry) string {
	return domainPathKey(e.Match.Domain, e.Match.Path)
}

func domainPathKey(domain, path string) string {
	return domain + "\x00" + path
}

func splitEntryKey(key string) (string, string) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

func conflictID(domain, path string) string {
	h := sha1.Sum([]byte(domainPathKey(domain, path)))
	return "conflict_" + hex.EncodeToString(h[:])[:12]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func resolutionHint(reasons []string) string {
	for _, reason := range reasons {
		if reason == "allow_exception conflicts with rewrite candidate" {
			return "disable the rewrite candidate or classify it as an allow_exception"
		}
	}
	return "align category or review_status on the conflicting entries"
}

func countImported(entries []rulecatalog.Entry) (unsupported, allow int) {
	for _, e := range entries {
		if e.Unsupported || e.Layer == rulecatalog.LayerDOM {
			unsupported++
		}
		if e.Category == "allow_exception" {
			allow++
		}
	}
	return
}

func largeChange(src Source, cfg config.AGHManagedScheduler) bool {
	if !cfg.LargeChangeRequiresReview {
		return false
	}
	if cfg.LargeChangeThresholdCount > 0 && src.Removed+src.Changed >= cfg.LargeChangeThresholdCount {
		return true
	}
	if cfg.LargeChangeThresholdPercent <= 0 || src.Entries == 0 {
		return false
	}
	return (src.Removed+src.Changed)*100/src.Entries >= cfg.LargeChangeThresholdPercent
}

func rewriteEnabled(e rulecatalog.Entry, ov CatalogOverride, cfg config.AGHManagedConfig) bool {
	if ov.RewriteEnabled != nil {
		return *ov.RewriteEnabled
	}
	switch nonempty(cfg.DefaultPreset, "balanced") {
	case "conservative":
		return e.ReviewStatus == rulecatalog.ReviewApproved && e.Verified
	case "aggressive":
		return e.ReviewStatus != rulecatalog.ReviewRejected && e.ReviewStatus != rulecatalog.ReviewDisabled
	default:
		return e.ReviewStatus == rulecatalog.ReviewApproved || e.ReviewStatus == rulecatalog.ReviewNeedsTest || (e.ReviewStatus == rulecatalog.ReviewCandidate && confidenceAtLeast(e.Confidence, "medium"))
	}
}

func confidenceAtLeast(got, min string) bool {
	rank := func(v string) int {
		switch strings.ToLower(v) {
		case "low":
			return 1
		case "medium", "":
			return 2
		case "high":
			return 3
		default:
			return 0
		}
	}
	return rank(got) >= rank(min)
}

func mergeOverride(dst *CatalogOverride, src CatalogOverride) {
	if src.Category != "" {
		dst.Category = src.Category
	}
	if src.ResourceType != "" {
		dst.ResourceType = src.ResourceType
	}
	if src.Risk != "" {
		dst.Risk = src.Risk
	}
	if src.Confidence != "" {
		dst.Confidence = src.Confidence
	}
	if src.ReviewStatus != "" {
		dst.ReviewStatus = src.ReviewStatus
	}
	if src.Verified != nil {
		dst.Verified = src.Verified
	}
	if src.ExpectedCatalog != "" {
		dst.ExpectedCatalog = src.ExpectedCatalog
	}
	if src.Action != "" {
		dst.Action = src.Action
	}
	if src.RewriteEnabled != nil {
		dst.RewriteEnabled = src.RewriteEnabled
	}
	if src.RewriteReason != "" {
		dst.RewriteReason = src.RewriteReason
	}
	if src.Notes != "" {
		dst.Notes = src.Notes
	}
}

func setLastChangedBy(dst *CatalogOverride, changedBy ...string) {
	if len(changedBy) == 0 {
		return
	}
	if actor := strings.TrimSpace(changedBy[0]); actor != "" {
		dst.LastChangedBy = actor
	}
}

func nextSync(interval, jitter string) time.Time {
	d := durationOr(interval, 12*time.Hour)
	j := durationOr(jitter, 0)
	if j > 0 {
		d += time.Duration(rand.Int63n(int64(j)))
	}
	return time.Now().Add(d)
}

func durationOr(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err == nil {
		return d
	}
	if strings.HasSuffix(raw, "d") {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSuffix(raw, "d"), "%d", &n); err == nil {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	return fallback
}

func staleSourceDuration(raw string) time.Duration {
	if raw == "0" {
		return 0
	}
	return durationOr(raw, 72*time.Hour)
}

func validSourceType(typ string) bool {
	switch typ {
	case SourceFilterURL, SourceManual, SourceAGHCustomRules, SourceAGHQueryLogCNAME:
		return true
	default:
		return false
	}
}

func validStaleFeedPolicy(policy string) bool {
	switch policy {
	case StaleFeedPolicyExclude, StaleFeedPolicyKeep:
		return true
	default:
		return false
	}
}

func isRemoteSource(typ string) bool {
	switch typ {
	case SourceFilterURL, SourceAGHCustomRules, SourceAGHQueryLogCNAME:
		return true
	default:
		return false
	}
}

func isStaleSource(src Source, ttl time.Duration) bool {
	return ttl > 0 && isRemoteSource(src.Type) && !src.LastSuccess.IsZero() && time.Since(src.LastSuccess) > ttl
}

func staleFeedPolicy(src Source) string {
	if src.StaleFeedPolicy == "" {
		return StaleFeedPolicyExclude
	}
	return src.StaleFeedPolicy
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

func staticIPStrings(cfg config.AGHManagedConfig) []string {
	raw := append(append([]string{}, cfg.StaticIPv4...), cfg.StaticIPv6...)
	ips := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ipStrings(ips)
}

func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// ParseManualDomains converts one-domain-per-line input into AdGuard-style
// rules. It is useful for UI callers building a manual source.
func ParseManualDomains(r io.Reader) string {
	var b strings.Builder
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		d := strings.TrimSpace(sc.Text())
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		if strings.HasPrefix(d, "||") || strings.Contains(d, " ") {
			b.WriteString(d)
		} else {
			b.WriteString("||")
			b.WriteString(d)
			b.WriteString("^")
		}
		b.WriteByte('\n')
	}
	return b.String()
}
