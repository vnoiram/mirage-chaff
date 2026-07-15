package rulecatalog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Build fetches configured sources and converts them into normalized entries.
func Build(cfg SyncConfig) ([]Entry, int, error) {
	var out []Entry
	sources := 0
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Enabled && cfg.BaseURL != "" && (cfg.SyncFilters || cfg.SyncCustomRules) {
		filterURLs, customRules, err := fetchAGHFilteringStatus(client, cfg.BaseURL)
		if err != nil {
			return nil, sources, err
		}
		if cfg.SyncFilters {
			cfg.FilterURLs = append(cfg.FilterURLs, filterURLs...)
		}
		if cfg.SyncCustomRules {
			cfg.CustomRules = append(cfg.CustomRules, customRules...)
		}
	}
	if cfg.SyncFilters {
		for _, u := range cfg.FilterURLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			body, err := fetch(client, u)
			if err != nil {
				return nil, sources, err
			}
			src := Source{Type: "adguard_filter", URL: u, Name: u}
			entries, err := ParseRules(strings.NewReader(body), src)
			if err != nil {
				return nil, sources, err
			}
			out = append(out, entries...)
			sources++
		}
	}
	if cfg.SyncCustomRules && len(cfg.CustomRules) > 0 {
		src := Source{Type: "adguard_custom", Name: "custom_rules"}
		entries, err := ParseRules(strings.NewReader(strings.Join(cfg.CustomRules, "\n")), src)
		if err != nil {
			return nil, sources, err
		}
		out = append(out, entries...)
		sources++
	}
	if cfg.Enabled && cfg.SyncQueryLog && cfg.CNAMEEnabled && cfg.CNAMEUseQueryLog && cfg.BaseURL != "" {
		entries, err := fetchAGHQueryLogCNAME(client, cfg.BaseURL)
		if err != nil {
			return nil, sources, err
		}
		if len(entries) > 0 {
			out = append(out, entries...)
			sources++
		}
	}
	return mergePriority(out), sources, nil
}

type aghFilteringStatus struct {
	Filters []struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"url"`
		Name    string `json:"name"`
	} `json:"filters"`
	UserRules       []string `json:"user_rules"`
	AllowlistRules  []string `json:"allowlist_rules"`
	BlockedServices []string `json:"blocked_services"`
}

func fetchAGHFilteringStatus(client *http.Client, base string) ([]string, []string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/control/filtering/status")
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, nil, fmt.Errorf("fetch AGH filtering status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("fetch AGH filtering status: status %d", resp.StatusCode)
	}
	var st aghFilteringStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&st); err != nil {
		return nil, nil, fmt.Errorf("parse AGH filtering status: %w", err)
	}
	var urls []string
	for _, f := range st.Filters {
		if f.Enabled && f.URL != "" {
			urls = append(urls, f.URL)
		}
	}
	rules := append([]string{}, st.UserRules...)
	rules = append(rules, st.AllowlistRules...)
	return urls, rules, nil
}

type aghQueryLog struct {
	Data []struct {
		Question struct {
			Name string `json:"name"`
		} `json:"question"`
		Answer []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"answer"`
		Reason string `json:"reason"`
	} `json:"data"`
}

func fetchAGHQueryLogCNAME(client *http.Client, base string) ([]Entry, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/control/querylog")
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("fetch AGH query log: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch AGH query log: status %d", resp.StatusCode)
	}
	var ql aghQueryLog
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&ql); err != nil {
		return nil, fmt.Errorf("parse AGH query log: %w", err)
	}
	var out []Entry
	for _, row := range ql.Data {
		domain := strings.TrimSuffix(strings.ToLower(row.Question.Name), ".")
		if domain == "" {
			continue
		}
		chain := []string{domain}
		target := ""
		for _, ans := range row.Answer {
			if strings.EqualFold(ans.Type, "CNAME") && ans.Value != "" {
				target = strings.TrimSuffix(strings.ToLower(ans.Value), ".")
				chain = append(chain, target)
			}
		}
		if target == "" {
			continue
		}
		conf := "medium"
		if safeCNAMEHost(target) {
			conf = "low"
		}
		e := Entry{
			Source:       Source{Type: "adguard_query_log", Name: "query_log"},
			OriginalRule: row.Reason,
			Match:        Match{Domain: domain},
			Layer:        LayerDNS, ResourceType: "domain", Category: "tracker", Risk: "medium", Confidence: conf,
			CNAMEChain: chain, CNAMETarget: target, CNAMEConfidence: conf,
			CloakingDetected: !safeCNAMEHost(target),
			ActionCandidates: []string{"agh-rewrite", "agh-custom-rule"},
			RewriteState:     "agh_rewrite_candidate",
			AGHQueryLogRef:   domain,
		}
		out = append(out, normalize(e))
	}
	for i := range out {
		out[i].ID = stableID(out[i])
	}
	return out, nil
}

func fetch(client *http.Client, rawurl string) (string, error) {
	resp, err := client.Get(rawurl)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", rawurl, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch %s: status %d", rawurl, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseRules handles the common subset needed for catalog metadata:
// Adblock/AdGuard domain rules, hosts files, RPZ CNAME blocks, and DOM selectors.
func ParseRules(r io.Reader, src Source) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "# ") {
			continue
		}
		if e, ok := parseAdblock(line, src); ok {
			out = append(out, e)
			continue
		}
		if e, ok := parseHosts(line, src); ok {
			out = append(out, e)
			continue
		}
		if e, ok := parseRPZ(line, src); ok {
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i] = normalize(out[i])
		out[i].ID = stableID(out[i])
	}
	return out, nil
}

func parseAdblock(line string, src Source) (Entry, bool) {
	allow := strings.HasPrefix(line, "@@")
	raw := strings.TrimPrefix(line, "@@")
	if strings.Contains(raw, "##") || strings.Contains(raw, "#?#") {
		parts := strings.SplitN(raw, "#", 2)
		domain := strings.TrimPrefix(parts[0], "||")
		return Entry{
			Source: src, OriginalRule: line, Match: Match{Domain: domain},
			Layer: LayerDOM, ResourceType: "dom", Category: "dom_selector", Risk: "low",
			Confidence: "high", Unsupported: true, ActionCandidates: []string{"unsupported-layer"},
			RewriteState: "unsupported_layer",
		}, domain != ""
	}
	if !strings.HasPrefix(raw, "||") {
		return Entry{}, false
	}
	body := strings.TrimPrefix(raw, "||")
	rulePart, opts, _ := strings.Cut(body, "$")
	domain := rulePart
	path := ""
	if i := strings.IndexAny(rulePart, "^/"); i >= 0 {
		domain = rulePart[:i]
		path = strings.Trim(strings.TrimPrefix(rulePart[i:], "^"), "*")
	}
	domain = strings.Trim(domain, "|^*/")
	if domain == "" {
		return Entry{}, false
	}
	e := Entry{
		Source: src, OriginalRule: line, Match: Match{Domain: domain, Path: path},
		Layer: LayerDNS, Category: "tracker", Risk: "medium", Confidence: "medium",
		ActionCandidates: []string{"stub", "forward-asis"}, RewriteState: "candidate",
	}
	if allow {
		e.Category = "allow_exception"
		e.Risk = "low"
		e.ReviewStatus = ReviewApproved
		e.Verified = true
		e.ActionCandidates = []string{"allow", "forward-asis"}
		e.RewriteState = "allow"
		return e, true
	}
	opts = strings.ToLower(opts)
	switch {
	case strings.Contains(opts, "script"):
		e.Layer = LayerHTTP
		e.ResourceType = "script"
		e.Category = "ad_sdk"
		e.Risk = "high"
		e.ActionCandidates = []string{"empty-js", "noop-sdk", "forward-asis"}
		e.ExpectedCatalog = "noop-sdk"
		e.JSAPIShape = "unknown noop-compatible API"
		e.StubTemplate = "generic-noop-v1"
	case strings.Contains(opts, "image"):
		e.Layer = LayerHTTP
		e.ResourceType = "image"
		e.Category = "tracking_pixel"
		e.ActionCandidates = []string{"stub:pixel", "forward-asis"}
		e.ExpectedCatalog = "pixel"
	case strings.Contains(opts, "xmlhttprequest") || strings.Contains(opts, "ping"):
		e.Layer = LayerHTTP
		e.ResourceType = "beacon"
		e.ActionCandidates = []string{"stub:beacon-204", "forward-asis"}
		e.ExpectedCatalog = "beacon-204"
	}
	return e, true
}

func parseHosts(line string, src Source) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Entry{}, false
	}
	ip := fields[0]
	if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::" && ip != "::1" {
		return Entry{}, false
	}
	domain := strings.TrimSuffix(fields[1], ".")
	if domain == "localhost" || strings.Contains(domain, ":") {
		return Entry{}, false
	}
	return Entry{
		Source: src, OriginalRule: line, Match: Match{Domain: domain},
		Layer: LayerDNS, Category: "tracker", ResourceType: "domain", Risk: "medium",
		Confidence: "high", ActionCandidates: []string{"agh-custom-rule", "stub:beacon-204"},
		RewriteState: "candidate",
	}, true
}

func parseRPZ(line string, src Source) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return Entry{}, false
	}
	if strings.ToUpper(fields[1]) != "CNAME" {
		return Entry{}, false
	}
	domain := strings.TrimSuffix(fields[0], ".")
	target := strings.TrimSuffix(fields[2], ".")
	e := Entry{
		Source: src, OriginalRule: line, Match: Match{Domain: domain},
		Layer: LayerDNS, Category: "tracker", ResourceType: "domain", Risk: "medium",
		Confidence: "high", ActionCandidates: []string{"agh-rewrite", "agh-custom-rule"},
		RewriteState: "candidate",
	}
	if target != "" && target != "*" {
		e.CNAMETarget = target
		e.CNAMEChain = []string{domain, target}
		e.CloakingDetected = target != "."
	}
	return e, domain != ""
}

func mergePriority(entries []Entry) []Entry {
	byKey := map[string]Entry{}
	for _, e := range entries {
		key := e.Match.Domain + "\x00" + e.Match.Path
		prev, ok := byKey[key]
		if !ok || priority(e) >= priority(prev) {
			byKey[key] = e
		}
	}
	out := make([]Entry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, e)
	}
	return out
}

func priority(e Entry) int {
	if e.Category == "allow_exception" {
		return 100
	}
	if e.Source.Type == "adguard_custom" {
		return 80
	}
	if e.Layer == LayerHTTP {
		return 60
	}
	return 10
}
