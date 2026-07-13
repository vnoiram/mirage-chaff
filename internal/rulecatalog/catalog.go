// Package rulecatalog stores DNS/adblock-derived metadata separately from the
// HTTP response catalog. AdGuard Home remains the DNS enforcement point; this
// catalog is explanatory data for fallback, triage, analytics, and review.
package rulecatalog

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	LayerDNS  = "dns"
	LayerHTTP = "http"
	LayerDOM  = "dom"

	ReviewCandidate = "candidate"
	ReviewApproved  = "approved"
	ReviewRejected  = "rejected"
	ReviewNeedsTest = "needs_test"
	ReviewDisabled  = "disabled"
)

// Source identifies where an entry came from.
type Source struct {
	Type string `json:"type" yaml:"type"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	URL  string `json:"url,omitempty" yaml:"url,omitempty"`
}

// Match is the normalized match shape mirage can reason about.
type Match struct {
	Domain string `json:"domain" yaml:"domain"`
	Path   string `json:"path,omitempty" yaml:"path,omitempty"`
}

// Entry is one normalized rule-catalog item.
type Entry struct {
	ID                 string    `json:"id" yaml:"id"`
	Source             Source    `json:"source" yaml:"source"`
	OriginalRule       string    `json:"original_rule,omitempty" yaml:"original_rule,omitempty"`
	Match              Match     `json:"match" yaml:"match"`
	Category           string    `json:"category,omitempty" yaml:"category,omitempty"`
	Layer              string    `json:"layer,omitempty" yaml:"layer,omitempty"`
	ResourceType       string    `json:"resource_type,omitempty" yaml:"resource_type,omitempty"`
	Risk               string    `json:"risk,omitempty" yaml:"risk,omitempty"`
	Confidence         string    `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	ReviewStatus       string    `json:"review_status,omitempty" yaml:"review_status,omitempty"`
	Verified           bool      `json:"verified" yaml:"verified"`
	ActionCandidates   []string  `json:"action_candidates,omitempty" yaml:"action_candidates,omitempty"`
	ExpectedCatalog    string    `json:"expected_catalog,omitempty" yaml:"expected_catalog,omitempty"`
	RewriteState       string    `json:"rewrite_state,omitempty" yaml:"rewrite_state,omitempty"`
	CNAMEChain         []string  `json:"cname_chain,omitempty" yaml:"cname_chain,omitempty"`
	CNAMETarget        string    `json:"cname_target,omitempty" yaml:"cname_target,omitempty"`
	CloakingDetected   bool      `json:"cloaking_detected,omitempty" yaml:"cloaking_detected,omitempty"`
	TrackerVendor      string    `json:"tracker_vendor,omitempty" yaml:"tracker_vendor,omitempty"`
	CNAMEConfidence    string    `json:"cname_confidence,omitempty" yaml:"cname_confidence,omitempty"`
	AGHQueryLogRef     string    `json:"agh_query_log_ref,omitempty" yaml:"agh_query_log_ref,omitempty"`
	JSGlobals          []string  `json:"js_globals,omitempty" yaml:"js_globals,omitempty"`
	JSAPIShape         string    `json:"js_api_shape,omitempty" yaml:"js_api_shape,omitempty"`
	StubTemplate       string    `json:"stub_template,omitempty" yaml:"stub_template,omitempty"`
	TestedSites        []string  `json:"tested_sites,omitempty" yaml:"tested_sites,omitempty"`
	FailureMode        string    `json:"failure_mode,omitempty" yaml:"failure_mode,omitempty"`
	PromotionCount     int       `json:"promotion_count,omitempty" yaml:"promotion_count,omitempty"`
	DemotionCount      int       `json:"demotion_count,omitempty" yaml:"demotion_count,omitempty"`
	TempAllowCount     int       `json:"temp_allow_count,omitempty" yaml:"temp_allow_count,omitempty"`
	FalsePositiveCount int       `json:"false_positive_count,omitempty" yaml:"false_positive_count,omitempty"`
	Unsupported        bool      `json:"unsupported,omitempty" yaml:"unsupported"`
	UpdatedAt          time.Time `json:"updated_at" yaml:"updated_at"`
}

// Status describes the last sync attempt.
type Status struct {
	LastRun      time.Time `json:"last_run,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	Entries      int       `json:"entries"`
	Sources      int       `json:"sources"`
	AGHEnabled   bool      `json:"agh_enabled"`
	QueryLogSync bool      `json:"query_log_sync"`
}

// Store is a small JSON-backed catalog optimized for admin/reload workflows.
type Store struct {
	path    string
	mu      sync.RWMutex
	entries map[string]Entry
	status  Status
}

// Open loads or creates a JSON-backed catalog store.
func Open(path string) (*Store, error) {
	s := &Store{path: path, entries: map[string]Entry{}}
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		var data struct {
			Entries []Entry `json:"entries"`
			Status  Status  `json:"status"`
		}
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("parse rule catalog: %w", err)
		}
		for _, e := range data.Entries {
			if e.ID == "" {
				e.ID = stableID(e)
			}
			s.entries[e.ID] = normalize(e)
		}
		s.status = data.Status
		s.status.Entries = len(s.entries)
		return s, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Replace swaps the store contents and persists them.
func (s *Store) Replace(entries []Entry, st Status) error {
	next := make(map[string]Entry, len(entries))
	for _, e := range entries {
		e = normalize(e)
		if e.ID == "" {
			e.ID = stableID(e)
		}
		next[e.ID] = e
	}
	st.Entries = len(next)
	s.mu.Lock()
	s.entries = next
	s.status = st
	err := s.saveLocked()
	s.mu.Unlock()
	return err
}

// Upsert writes a single entry.
func (s *Store) Upsert(e Entry) error {
	e = normalize(e)
	if e.ID == "" {
		e.ID = stableID(e)
	}
	s.mu.Lock()
	s.entries[e.ID] = e
	s.status.Entries = len(s.entries)
	err := s.saveLocked()
	s.mu.Unlock()
	return err
}

// Review updates review metadata without changing the source rule.
func (s *Store) Review(id, status string, verified *bool) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, os.ErrNotExist
	}
	switch status {
	case "", ReviewCandidate, ReviewApproved, ReviewRejected, ReviewNeedsTest, ReviewDisabled:
	default:
		return Entry{}, fmt.Errorf("invalid review_status %q", status)
	}
	if status != "" {
		e.ReviewStatus = status
	}
	if verified != nil {
		e.Verified = *verified
	}
	e.UpdatedAt = time.Now()
	s.entries[id] = e
	return e, s.saveLocked()
}

// Promote marks a candidate as verified and approved.
func (s *Store) Promote(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, os.ErrNotExist
	}
	e.Verified = true
	e.ReviewStatus = ReviewApproved
	e.PromotionCount++
	e.UpdatedAt = time.Now()
	s.entries[id] = e
	return e, s.saveLocked()
}

// Downgrade disables or de-verifies a catalog entry after a false positive.
func (s *Store) Downgrade(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, os.ErrNotExist
	}
	e.Verified = false
	e.ReviewStatus = ReviewDisabled
	e.DemotionCount++
	e.FalsePositiveCount++
	e.UpdatedAt = time.Now()
	s.entries[id] = e
	return e, s.saveLocked()
}

// MarkCNAME records CNAME cloaking metadata on an entry without changing DNS.
func (s *Store) MarkCNAME(id string, chain []string, target, vendor, confidence, queryRef string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return Entry{}, os.ErrNotExist
	}
	e.CNAMEChain = cleanChain(chain)
	e.CNAMETarget = strings.TrimSuffix(strings.ToLower(target), ".")
	e.TrackerVendor = vendor
	e.CNAMEConfidence = confidence
	e.AGHQueryLogRef = queryRef
	e.CloakingDetected = e.CNAMETarget != "" && !safeCNAMEHost(e.CNAMETarget)
	if e.CloakingDetected && e.RewriteState == "" {
		e.RewriteState = "agh_rewrite_candidate"
	}
	e.UpdatedAt = time.Now()
	s.entries[id] = e
	return e, s.saveLocked()
}

// RewriteCandidate returns a non-destructive AGH custom rule/rewrite suggestion.
func (s *Store) RewriteCandidate(id string) (map[string]string, error) {
	s.mu.RLock()
	e, ok := s.entries[id]
	s.mu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	domain := e.Match.Domain
	if domain == "" {
		return nil, fmt.Errorf("entry has no domain")
	}
	rule := "||" + domain + "^"
	if e.Category == "allow_exception" {
		rule = "@@" + rule
	}
	return map[string]string{
		"domain":            domain,
		"custom_rule":       rule,
		"rewrite_candidate": domain + " A <mirage-chaff-ip>",
		"note":              "candidate only; mirage-chaff does not write AdGuard Home rewrites automatically",
	}, nil
}

// List returns all entries, optionally filtered by query parameters.
func (s *Store) List(filter map[string]string) []Entry {
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if matchesFilter(e, filter) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Match.Domain != out[j].Match.Domain {
			return out[i].Match.Domain < out[j].Match.Domain
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns one entry.
func (s *Store) Get(id string) (Entry, bool) {
	s.mu.RLock()
	e, ok := s.entries[id]
	s.mu.RUnlock()
	return e, ok
}

// Lookup finds the best metadata for a request.
func (s *Store) Lookup(domain, path string) (Entry, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best Entry
	bestScore := -1
	for _, e := range s.entries {
		if e.Match.Domain == "" || !domainMatches(domain, e.Match.Domain) {
			continue
		}
		score := len(e.Match.Domain)
		if e.Match.Path != "" {
			if !strings.HasPrefix(path, e.Match.Path) && !strings.Contains(path, e.Match.Path) {
				continue
			}
			score += len(e.Match.Path) + 1000
		}
		if score > bestScore {
			best = e
			bestScore = score
		}
	}
	return best, bestScore >= 0
}

// Status returns last sync state.
func (s *Store) Status() Status {
	s.mu.RLock()
	st := s.status
	st.Entries = len(s.entries)
	s.mu.RUnlock()
	return st
}

// Analytics summarizes catalog classifications.
func (s *Store) Analytics() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	countBy := func(field func(Entry) string) map[string]int {
		m := map[string]int{}
		for _, e := range s.entries {
			k := field(e)
			if k == "" {
				k = "unknown"
			}
			m[k]++
		}
		return m
	}
	var highUnverified, unsupportedDOM, cname, jsFailures []Entry
	for _, e := range s.entries {
		if e.Risk == "high" && !e.Verified {
			highUnverified = append(highUnverified, e)
		}
		if e.Layer == LayerDOM || e.Unsupported {
			unsupportedDOM = append(unsupportedDOM, e)
		}
		if e.CloakingDetected || e.CNAMETarget != "" {
			cname = append(cname, e)
		}
		if e.ResourceType == "script" && (e.FailureMode != "" || !e.Verified) {
			jsFailures = append(jsFailures, e)
		}
	}
	return map[string]any{
		"total":               len(s.entries),
		"by_category":         countBy(func(e Entry) string { return e.Category }),
		"by_risk":             countBy(func(e Entry) string { return e.Risk }),
		"by_verified":         map[string]int{"true": countBool(s.entries, true), "false": countBool(s.entries, false)},
		"by_review_status":    countBy(func(e Entry) string { return e.ReviewStatus }),
		"by_source_type":      countBy(func(e Entry) string { return e.Source.Type }),
		"by_resource_type":    countBy(func(e Entry) string { return e.ResourceType }),
		"by_expected_catalog": countBy(func(e Entry) string { return e.ExpectedCatalog }),
		"high_unverified":     limitEntries(highUnverified, 50),
		"unsupported_dom":     limitEntries(unsupportedDOM, 50),
		"cname_candidates":    limitEntries(cname, 50),
		"js_stub_candidates":  limitEntries(jsFailures, 50),
	}
}

// VerifiedStubCatalog returns a catalog name only for verified script metadata.
func (e Entry) VerifiedStubCatalog(site string) (string, bool) {
	if !e.Verified || e.ResourceType != "script" || e.ExpectedCatalog == "" || e.ReviewStatus == ReviewDisabled {
		return "", false
	}
	if len(e.TestedSites) == 0 {
		return e.ExpectedCatalog, true
	}
	site = strings.ToLower(strings.TrimSuffix(site, "."))
	for _, tested := range e.TestedSites {
		tested = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(tested), "."))
		if tested == "" {
			continue
		}
		if site == tested || strings.HasSuffix(site, "."+tested) {
			return e.ExpectedCatalog, true
		}
	}
	return "", false
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	entries := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	raw, err := json.MarshalIndent(struct {
		Entries []Entry `json:"entries"`
		Status  Status  `json:"status"`
	}{entries, s.status}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Sync fetches configured rule sources and replaces the store.
func (s *Store) Sync(cfg SyncConfig) Status {
	st := Status{LastRun: time.Now(), AGHEnabled: cfg.Enabled, QueryLogSync: cfg.SyncQueryLog}
	entries, sources, err := Build(cfg)
	st.Sources = sources
	if err != nil {
		st.LastError = err.Error()
		_ = s.Replace(s.List(nil), st)
		return st
	}
	st.LastSuccess = st.LastRun
	if err := s.Replace(entries, st); err != nil {
		st.LastError = err.Error()
		_ = s.Replace(entries, st)
		return st
	}
	return s.Status()
}

// SyncConfig is a local copy of config.AGHSyncConfig to avoid import cycles.
type SyncConfig struct {
	Enabled          bool
	BaseURL          string
	SyncFilters      bool
	SyncCustomRules  bool
	SyncAllowDeny    bool
	SyncQueryLog     bool
	CNAMEEnabled     bool
	CNAMEUseQueryLog bool
	FilterURLs       []string
	CustomRules      []string
	Client           *http.Client
}

func normalize(e Entry) Entry {
	e.Match.Domain = strings.ToLower(strings.TrimSuffix(e.Match.Domain, "."))
	if e.Layer == "" {
		e.Layer = LayerDNS
	}
	if e.Category == "" {
		e.Category = "tracker"
	}
	if e.Risk == "" {
		e.Risk = "medium"
	}
	if e.Confidence == "" {
		e.Confidence = "medium"
	}
	if e.ReviewStatus == "" {
		e.ReviewStatus = ReviewCandidate
	}
	if e.UpdatedAt.IsZero() {
		e.UpdatedAt = time.Now()
	}
	if e.ExpectedCatalog == "" && e.ResourceType == "script" && e.Verified {
		e.ExpectedCatalog = "noop-sdk"
	}
	if e.CNAMEConfidence == "" && e.CNAMETarget != "" {
		e.CNAMEConfidence = e.Confidence
	}
	return e
}

func cleanChain(in []string) []string {
	var out []string
	for _, v := range in {
		v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func safeCNAMEHost(host string) bool {
	host = strings.ToLower(host)
	for _, token := range []string{"cdn", "static", "assets", "login", "accounts", "auth"} {
		if strings.Contains(host, token) {
			return true
		}
	}
	return false
}

func stableID(e Entry) string {
	h := sha1.Sum([]byte(e.Source.Type + "\x00" + e.Source.Name + "\x00" + e.OriginalRule + "\x00" + e.Match.Domain + "\x00" + e.Match.Path))
	return "rc_" + hex.EncodeToString(h[:])[:16]
}

func domainMatches(domain, pattern string) bool {
	pattern = strings.TrimPrefix(strings.TrimPrefix(pattern, "*."), ".")
	return domain == pattern || strings.HasSuffix(domain, "."+pattern)
}

func matchesFilter(e Entry, filter map[string]string) bool {
	for k, v := range filter {
		if v == "" {
			continue
		}
		switch k {
		case "domain":
			if !domainMatches(e.Match.Domain, v) && !domainMatches(v, e.Match.Domain) {
				return false
			}
		case "category":
			if e.Category != v {
				return false
			}
		case "risk":
			if e.Risk != v {
				return false
			}
		case "verified":
			if (v == "true") != e.Verified {
				return false
			}
		case "review_status":
			if e.ReviewStatus != v {
				return false
			}
		case "source_type":
			if e.Source.Type != v {
				return false
			}
		}
	}
	return true
}

func countBool(entries map[string]Entry, want bool) int {
	n := 0
	for _, e := range entries {
		if e.Verified == want {
			n++
		}
	}
	return n
}

func limitEntries(in []Entry, n int) []Entry {
	sort.Slice(in, func(i, j int) bool { return in[i].Match.Domain < in[j].Match.Domain })
	if len(in) > n {
		return in[:n]
	}
	return in
}
