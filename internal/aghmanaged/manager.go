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
	SourceFilterURL = "filter_url"
	SourceManual    = "manual"
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
	Priority         int       `json:"priority,omitempty"`
}

// FeedStatus summarizes generated feed state for the admin UI.
type FeedStatus struct {
	Enabled        bool      `json:"enabled"`
	FeedPath       string    `json:"feed_path"`
	TargetMode     string    `json:"target_mode"`
	TargetName     string    `json:"target_name"`
	ResolvedIPs    []string  `json:"resolved_ips,omitempty"`
	LastResolve    time.Time `json:"last_resolve,omitempty"`
	LastResolveErr string    `json:"last_resolve_error,omitempty"`
	ItemCount      int       `json:"item_count"`
	ExcludedCount  int       `json:"excluded_count"`
	EmergencyEmpty bool      `json:"emergency_empty"`
	Sources        int       `json:"sources"`
	LastGenerated  time.Time `json:"last_generated,omitempty"`
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
	SourceIDs      []string `json:"source_ids,omitempty"`
	RewriteEnabled bool     `json:"rewrite_enabled"`
	RewriteReason  string   `json:"rewrite_reason,omitempty"`
}

type state struct {
	Sources        []Source                       `json:"sources"`
	Entries        []rulecatalog.Entry            `json:"entries"`
	Pending        map[string][]rulecatalog.Entry `json:"pending,omitempty"`
	Overrides      map[string]CatalogOverride     `json:"overrides,omitempty"`
	EmergencyEmpty *bool                          `json:"emergency_empty,omitempty"`
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
}

// Manager stores sources, imports entries, and generates AGH rewrite feeds.
type Manager struct {
	path     string
	cfg      config.AGHManagedConfig
	resolver Resolver
	client   *http.Client

	mu        sync.RWMutex
	sources   map[string]Source
	entries   map[string]rulecatalog.Entry
	pending   map[string][]rulecatalog.Entry
	overrides map[string]CatalogOverride

	targetIPs      []net.IP
	lastResolve    time.Time
	lastResolveErr string
	lastGenerated  time.Time
}

// Open loads or creates a manager store.
func Open(path string, cfg config.AGHManagedConfig, res Resolver) (*Manager, error) {
	m := &Manager{
		path:      path,
		cfg:       cfg,
		resolver:  res,
		client:    &http.Client{Timeout: durationOr(cfg.Scheduler.SyncTimeout, 30*time.Second)},
		sources:   map[string]Source{},
		entries:   map[string]rulecatalog.Entry{},
		pending:   map[string][]rulecatalog.Entry{},
		overrides: map[string]CatalogOverride{},
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
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
	if src.Type != SourceFilterURL && src.Type != SourceManual {
		return Source{}, fmt.Errorf("invalid source type %q", src.Type)
	}
	if src.Type == SourceFilterURL && src.URL == "" {
		return Source{}, fmt.Errorf("url required")
	}
	if src.Type == SourceManual && src.Content == "" {
		return Source{}, fmt.Errorf("content required")
	}
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
		e = m.applyOverrideLocked(e)
		rows = append(rows, CatalogRow{
			Entry:          e,
			SourceIDs:      []string{e.Source.Name},
			RewriteEnabled: rewriteEnabled(e, m.overrides[e.ID], m.cfg),
			RewriteReason:  m.overrides[e.ID].RewriteReason,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Match.Domain != rows[j].Match.Domain {
			return rows[i].Match.Domain < rows[j].Match.Domain
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

func (m *Manager) PatchEntry(id string, ov CatalogOverride) (CatalogRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok {
		return CatalogRow{}, os.ErrNotExist
	}
	cur := m.overrides[id]
	mergeOverride(&cur, ov)
	m.overrides[id] = cur
	if err := m.saveLocked(); err != nil {
		return CatalogRow{}, err
	}
	e = m.applyOverrideLocked(e)
	return CatalogRow{Entry: e, SourceIDs: []string{e.Source.Name}, RewriteEnabled: rewriteEnabled(e, cur, m.cfg), RewriteReason: cur.RewriteReason}, nil
}

func (m *Manager) SetEmergencyEmpty(on bool) error {
	m.mu.Lock()
	m.cfg.EmergencyEmpty = on
	err := m.saveLocked()
	m.mu.Unlock()
	return err
}

func (m *Manager) Status(ctx context.Context) FeedStatus {
	p, _ := m.Generate(ctx, false)
	return p.Status
}

func (m *Manager) Generate(ctx context.Context, includeRows bool) (Preview, error) {
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
	sources := make([]Source, 0, len(m.sources))
	for _, src := range m.sources {
		sources = append(sources, src)
	}
	cachedIPs := append([]net.IP(nil), m.targetIPs...)
	lastResolve := m.lastResolve
	lastResolveErr := m.lastResolveErr
	m.mu.RUnlock()

	var ips []net.IP
	var resolveErr error
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
			}
		}
	}

	var b bytes.Buffer
	now := time.Now()
	status := FeedStatus{
		Enabled: cfg.Enabled, FeedPath: cfg.FeedPath, TargetMode: nonempty(cfg.TargetMode, "resolved_ip"),
		TargetName: cfg.TargetName, ResolvedIPs: ipStrings(ips), LastResolve: lastResolve,
		LastResolveErr: lastResolveErr, EmergencyEmpty: cfg.EmergencyEmpty, Sources: len(sources), LastGenerated: now,
	}
	fmt.Fprintf(&b, "! mirage-chaff managed rewrites\n! generated_at=%s\n! target_mode=%s target_name=%s\n", now.Format(time.RFC3339), status.TargetMode, cfg.TargetName)
	if cfg.EmergencyEmpty || !cfg.Enabled {
		fmt.Fprintf(&b, "! feed empty: enabled=%v emergency_empty=%v\n", cfg.Enabled, cfg.EmergencyEmpty)
		status.ExcludedCount = len(entries)
		return Preview{Status: status, Lines: b.String(), Sources: sources}, nil
	}
	if (cfg.TargetMode == "" || cfg.TargetMode == "resolved_ip") && len(ips) == 0 {
		return Preview{Status: status, Lines: b.String(), Sources: sources}, fmt.Errorf("target resolution failed: %s", lastResolveErr)
	}
	sourceByID := make(map[string]Source, len(sources))
	for _, src := range sources {
		sourceByID[src.ID] = src
	}
	staleSourceTTL := durationOr(cfg.Scheduler.StaleSourceTTL, 0)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Match.Domain != entries[j].Match.Domain {
			return entries[i].Match.Domain < entries[j].Match.Domain
		}
		return entries[i].ID < entries[j].ID
	})
	var items []FeedItem
	for _, e := range entries {
		ov := overrides[e.ID]
		item := m.feedItem(e, ov, cfg, ips)
		if staleSourceTTL > 0 {
			if src, ok := sourceByID[e.Source.Name]; ok && src.Type == SourceFilterURL && !src.LastSuccess.IsZero() && time.Since(src.LastSuccess) > staleSourceTTL {
				item.Included = false
				item.Reason = "stale source"
			}
		}
		if item.Included {
			for _, line := range item.Lines {
				fmt.Fprintf(&b, "! entry_id=%s source=%s category=%s confidence=%s\n%s\n", item.EntryID, strings.Join(item.SourceIDs, ","), item.Category, item.Confidence, line)
			}
			status.ItemCount++
		} else {
			status.ExcludedCount++
		}
		items = append(items, item)
	}
	m.mu.Lock()
	m.lastGenerated = now
	m.mu.Unlock()
	p := Preview{Status: status, Items: items, Lines: b.String(), Sources: sources}
	if includeRows {
		p.Entries = m.CatalogRows()
	}
	return p, nil
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

func (m *Manager) feedItem(e rulecatalog.Entry, ov CatalogOverride, cfg config.AGHManagedConfig, ips []net.IP) FeedItem {
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
	if e.Category == "allow_exception" {
		item.Reason = "allow exception"
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
	for _, src := range m.sources {
		st.Sources = append(st.Sources, src)
	}
	for _, e := range m.entries {
		st.Entries = append(st.Entries, e)
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
		return e.ReviewStatus == rulecatalog.ReviewCandidate || e.ReviewStatus == rulecatalog.ReviewApproved || e.ReviewStatus == rulecatalog.ReviewNeedsTest
	}
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

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
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
