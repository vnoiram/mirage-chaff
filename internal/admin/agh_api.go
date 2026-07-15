package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
