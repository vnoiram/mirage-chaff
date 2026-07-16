package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/config"
)

type aghAPIConfig struct {
	BaseURL string
	User    string
	Pass    string
}

type aghRefreshResult struct {
	BaseURL string `json:"base_url"`
	Force   bool   `json:"force"`
}

type aghFilterMatch struct {
	ID      int    `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	URL     string `json:"url,omitempty"`
	Enabled bool   `json:"enabled"`
}

type aghRegistrationStatus struct {
	BaseURL       string          `json:"base_url"`
	FeedURL       string          `json:"feed_url"`
	Registered    bool            `json:"registered"`
	Enabled       bool            `json:"enabled"`
	MatchedFilter *aghFilterMatch `json:"matched_filter,omitempty"`
}

type aghRegisterResult struct {
	aghRegistrationStatus
	AlreadyRegistered bool `json:"already_registered"`
	Refreshed         bool `json:"refreshed"`
}

type aghCheckHostResult struct {
	Domain string         `json:"domain"`
	Raw    map[string]any `json:"raw,omitempty"`
}

func refreshAGHFilters(ctx context.Context, client *http.Client, cfg config.AGHSyncConfig, force bool) (aghRefreshResult, error) {
	apiCfg, err := loadAGHAPIConfig(cfg)
	if err != nil {
		return aghRefreshResult{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	body, err := json.Marshal(map[string]bool{"force": force})
	if err != nil {
		return aghRefreshResult{}, err
	}
	url := strings.TrimRight(apiCfg.BaseURL, "/") + "/control/filtering/refresh"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return aghRefreshResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(apiCfg.User, apiCfg.Pass)
	resp, err := client.Do(req)
	if err != nil {
		return aghRefreshResult{}, fmt.Errorf("refresh AGH filters: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return aghRefreshResult{}, fmt.Errorf("refresh AGH filters: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return aghRefreshResult{BaseURL: apiCfg.BaseURL, Force: force}, nil
}

func checkAGHFeedRegistration(ctx context.Context, client *http.Client, cfg config.AGHSyncConfig, feedURL string) (aghRegistrationStatus, error) {
	apiCfg, err := loadAGHAPIConfig(cfg)
	if err != nil {
		return aghRegistrationStatus{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var response struct {
		Filters []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			URL     string `json:"url"`
			Enabled bool   `json:"enabled"`
		} `json:"filters"`
	}
	if err := doAGHJSON(ctx, client, apiCfg, http.MethodGet, "/control/filtering/status", nil, &response); err != nil {
		return aghRegistrationStatus{}, fmt.Errorf("check AGH feed registration: %w", err)
	}
	out := aghRegistrationStatus{BaseURL: apiCfg.BaseURL, FeedURL: feedURL}
	want := normalizeAGHURL(feedURL)
	for _, filter := range response.Filters {
		if normalizeAGHURL(filter.URL) != want {
			continue
		}
		matched := aghFilterMatch{ID: filter.ID, Name: filter.Name, URL: filter.URL, Enabled: filter.Enabled}
		out.Registered = true
		out.Enabled = filter.Enabled
		out.MatchedFilter = &matched
		break
	}
	return out, nil
}

func registerAGHFeed(ctx context.Context, client *http.Client, cfg config.AGHSyncConfig, feedURL, name string) (aghRegisterResult, error) {
	apiCfg, err := loadAGHAPIConfig(cfg)
	if err != nil {
		return aghRegisterResult{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	status, err := checkAGHFeedRegistration(ctx, client, cfg, feedURL)
	if err != nil {
		return aghRegisterResult{}, err
	}
	result := aghRegisterResult{aghRegistrationStatus: status}
	if status.Registered {
		result.AlreadyRegistered = true
		return result, nil
	}
	if strings.TrimSpace(name) == "" {
		name = "mirage-chaff managed rewrites"
	}
	body, err := json.Marshal(map[string]any{
		"name":      name,
		"url":       feedURL,
		"whitelist": false,
	})
	if err != nil {
		return aghRegisterResult{}, err
	}
	if err := doAGHJSON(ctx, client, apiCfg, http.MethodPost, "/control/filtering/add_url", bytes.NewReader(body), nil); err != nil {
		return aghRegisterResult{}, fmt.Errorf("register AGH feed: %w", err)
	}
	if _, err := refreshAGHFilters(ctx, client, cfg, false); err != nil {
		return aghRegisterResult{}, err
	}
	result.Refreshed = true
	status, err = checkAGHFeedRegistration(ctx, client, cfg, feedURL)
	if err != nil {
		return aghRegisterResult{}, err
	}
	result.aghRegistrationStatus = status
	return result, nil
}

func checkAGHHost(ctx context.Context, client *http.Client, cfg config.AGHSyncConfig, domain string) (aghCheckHostResult, error) {
	apiCfg, err := loadAGHAPIConfig(cfg)
	if err != nil {
		return aghCheckHostResult{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	path := "/control/filtering/check_host?name=" + url.QueryEscape(domain)
	var raw map[string]any
	if err := doAGHJSON(ctx, client, apiCfg, http.MethodGet, path, nil, &raw); err != nil {
		return aghCheckHostResult{}, fmt.Errorf("check AGH host: %w", err)
	}
	return aghCheckHostResult{Domain: domain, Raw: raw}, nil
}

func doAGHJSON(ctx context.Context, client *http.Client, cfg aghAPIConfig, method, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(cfg.User, cfg.Pass)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if dst == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return err
	}
	return nil
}

func normalizeAGHURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func loadAGHAPIConfig(cfg config.AGHSyncConfig) (aghAPIConfig, error) {
	out := aghAPIConfig{BaseURL: strings.TrimSpace(cfg.BaseURL)}
	if cfg.EnvFile != "" {
		raw, err := os.ReadFile(cfg.EnvFile)
		if err != nil && !os.IsNotExist(err) {
			return aghAPIConfig{}, fmt.Errorf("read AGH env file: %w", err)
		}
		if err == nil {
			env := parseAGHEnv(bytes.NewReader(raw))
			if v := strings.TrimSpace(env["AGH_API_URL"]); v != "" {
				out.BaseURL = v
			}
			out.User = env["AGH_API_USER"]
			out.Pass = env["AGH_API_PASS"]
		}
	}
	if out.BaseURL == "" {
		return aghAPIConfig{}, fmt.Errorf("agh api base_url required")
	}
	if out.User == "" || out.Pass == "" {
		return aghAPIConfig{}, fmt.Errorf("agh api credentials required")
	}
	return out, nil
}

func parseAGHEnv(r io.Reader) map[string]string {
	out := map[string]string{}
	raw, _ := io.ReadAll(r)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			quote := value[0]
			if (quote == '\'' || quote == '"') && value[len(value)-1] == quote {
				value = value[1 : len(value)-1]
			}
		}
		out[key] = value
	}
	return out
}
