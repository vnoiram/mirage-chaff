// Package config loads and validates mirage-chaff.conf.
//
// The on-disk config is TOML (see configs/mirage-chaff.conf.sample). Phase 0
// establishes the full config surface, sane defaults, and validation so that
// `mirage-chaff check` works end-to-end; the TOML decode step is wired in
// Phase 1 (marked TODO below) to keep the Phase 0 skeleton dependency-free and
// buildable offline.
//
// Reload semantics (see design doc "設定項目の反映方法"):
//   - Reload-safe (SIGHUP): policy.d, catalog, Mimic thresholds, Log, RateLimit,
//     Mode's stub-side switch.
//   - Restart-required: listener addresses/ports, Protocols.* (UDP443 socket
//     open/close, ALPN), Cert.KeyType, Admin bind/enabled, Observability bind.
//
// Fields carry a `reload:"safe"` or `reload:"restart"` tag to drive that
// classification programmatically and to power the admin UI "restart required"
// warning.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// SchemaVersion is the config schema version this binary understands (D-3).
// Unknown future versions produce a warning, not a hard failure.
const SchemaVersion = 1

// Config is the fully-resolved runtime configuration.
type Config struct {
	Version int `toml:"version" reload:"safe"`

	Listen         ListenConfig         `toml:"listen"`
	Protocols      ProtocolsConfig      `toml:"protocols"`
	Cert           CertConfig           `toml:"cert"`
	Upstream       UpstreamConfig       `toml:"upstream"`
	Mode           string               `toml:"mode" reload:"safe"` // "full" | "stub-only"
	Mimic          MimicConfig          `toml:"mimic"`
	Resources      ResourcesConfig      `toml:"resources"`
	Log            LogConfig            `toml:"log" reload:"safe"`
	Observability  ObservabilityConfig  `toml:"observability"`
	Admin          AdminConfig          `toml:"admin"`
	AGHManaged     AGHManagedConfig     `toml:"agh_managed_rewrites" reload:"safe"`
	Paths          PathsConfig          `toml:"paths"`
	AGHSync        AGHSyncConfig        `toml:"agh_sync" reload:"safe"`
	RuleCatalog    RuleCatalogConfig    `toml:"rule_catalog" reload:"safe"`
	UnknownProfile UnknownProfileConfig `toml:"unknown_profile" reload:"safe"`

	// path is the file this config was loaded from (empty if defaults-only).
	path string
}

// ListenConfig controls the intercept listeners (restart-required).
type ListenConfig struct {
	HTTP  string `toml:"http" reload:"restart"`  // e.g. ":80"
	HTTPS string `toml:"https" reload:"restart"` // e.g. ":443" (TCP+TLS)
	IPv6  bool   `toml:"ipv6" reload:"restart"`  // dual-stack v4/v6 (close IPv6 bypass)
}

// ProtocolsConfig toggles transport/application layers (all restart-required:
// they open/close sockets or change ALPN).
type ProtocolsConfig struct {
	HTTP1 bool `toml:"http1" reload:"restart"`
	HTTP2 bool `toml:"http2" reload:"restart"`
	QUIC  bool `toml:"quic" reload:"restart"`  // UDP443 QUIC transport listen
	HTTP3 bool `toml:"http3" reload:"restart"` // HTTP/3 termination (requires QUIC)
}

// CertConfig controls the intermediate CA and dynamic leaf issuance.
type CertConfig struct {
	IntermediateCert string `toml:"intermediate_cert" reload:"restart"` // /etc/mirage-chaff/ca/intermediate.crt
	IntermediateKey  string `toml:"intermediate_key" reload:"restart"`  // /etc/mirage-chaff/ca/intermediate.key
	KeyType          string `toml:"key_type" reload:"restart"`          // "ecdsa" (default) | "rsa"
	CacheMax         int    `toml:"cache_max" reload:"safe"`            // LRU leaf cache size
	CacheTTLHours    int    `toml:"cache_ttl_hours" reload:"safe"`
	CacheDir         string `toml:"cache_dir" reload:"restart"` // /var/lib/mirage-chaff/certcache
}

// UpstreamConfig is the INDEPENDENT resolver used for forward/passthrough real
// IP resolution. It must NOT be AdGuard Home (rewrite loop).
type UpstreamConfig struct {
	Resolvers []string `toml:"resolvers" reload:"safe"` // e.g. ["https://1.1.1.1/dns-query"]
}

// MimicConfig controls forward-mimic (shape-preserving decoys). Video mimic is
// opt-in and serves opaque range-consistent bytes, not playable media.
type MimicConfig struct {
	Enabled    bool  `toml:"enabled" reload:"safe"`
	MaxBytes   int64 `toml:"max_bytes" reload:"safe"`
	CacheMax   int   `toml:"cache_max" reload:"safe"`
	AllowVideo bool  `toml:"allow_video" reload:"safe"` // default false: video -> stub/asis
}

// ResourcesConfig caps concurrency and body sizes for constrained VMs.
type ResourcesConfig struct {
	MaxConns     int   `toml:"max_conns" reload:"safe"`
	RateLimit    int   `toml:"rate_limit" reload:"safe"`
	BodyMaxBytes int64 `toml:"body_max_bytes" reload:"safe"`
}

// LogConfig controls structured logging and redaction (reload-safe).
type LogConfig struct {
	Level      string       `toml:"level" reload:"safe"`     // "debug"|"info"|"warn"|"error"
	Mode       string       `toml:"mode" reload:"safe"`      // off|redacted|stats|debug|full
	Retention  string       `toml:"retention" reload:"safe"` // informational TTL, e.g. "7d"
	Redact     bool         `toml:"redact" reload:"safe"`    // mask sensitive URL/query/header values
	DebugScope []DebugScope `toml:"debug_scope" reload:"safe"`
}

// DebugScope enables detailed logging for a bounded domain/client scope.
type DebugScope struct {
	Domain string `toml:"domain" reload:"safe"`
	Client string `toml:"client" reload:"safe"`
	TTL    string `toml:"ttl" reload:"safe"`
}

// ObservabilityConfig is the admin-INDEPENDENT health/metrics listener (A-3).
// It must keep serving /-/healthy, /ready (and optionally /metrics) even when
// Admin.Enabled is false, so systemd watchdog + Uptime Kuma + Prometheus survive.
type ObservabilityConfig struct {
	Listen  string                     `toml:"listen" reload:"restart"` // e.g. "127.0.0.1:9256"
	Metrics bool                       `toml:"metrics" reload:"restart"`
	Catalog ObservabilityCatalogConfig `toml:"catalog" reload:"safe"`
}

// ObservabilityCatalogConfig controls catalog-derived metric/log enrichment.
type ObservabilityCatalogConfig struct {
	Enabled               bool     `toml:"enabled" reload:"safe"`
	PrometheusLabels      []string `toml:"prometheus_labels" reload:"safe"`
	EmitSIEMCatalogFields bool     `toml:"emit_siem_catalog_fields" reload:"safe"`
}

// AdminConfig controls the web admin UI (MITM control plane; localhost default).
type AdminConfig struct {
	Enabled       bool       `toml:"enabled" reload:"restart"`
	Listen        string     `toml:"listen" reload:"restart"`         // e.g. "127.0.0.1:8443"
	SecureCookies bool       `toml:"secure_cookies" reload:"restart"` // true behind TLS/HTTPS proxy deployments
	OIDC          OIDCConfig `toml:"oidc"`
}

// OIDCConfig enables SSO login mapping OIDC groups to RBAC roles (design doc §7).
// Local accounts remain a fallback.
type OIDCConfig struct {
	Enabled      bool              `toml:"enabled" reload:"restart"`
	Issuer       string            `toml:"issuer" reload:"restart"`
	ClientID     string            `toml:"client_id" reload:"restart"`
	ClientSecret string            `toml:"client_secret" reload:"restart"`
	RedirectURL  string            `toml:"redirect_url" reload:"restart"`
	GroupsClaim  string            `toml:"groups_claim" reload:"restart"` // default "groups"
	RoleMap      map[string]string `toml:"role_map" reload:"restart"`     // oidc group -> admin|editor|viewer
}

// PathsConfig holds on-disk locations the daemon reads/writes.
type PathsConfig struct {
	PolicyDir  string `toml:"policy_dir" reload:"safe"`  // /etc/mirage-chaff/policy.d
	CatalogDir string `toml:"catalog_dir" reload:"safe"` // /etc/mirage-chaff/catalog
	StateDir   string `toml:"state_dir" reload:"restart"`
	AGHEnv     string `toml:"agh_env" reload:"safe"` // /etc/mirage-chaff/agh.env (kill-switch creds)
}

// AGHSyncConfig mirrors AdGuard Home rule sources into the local rule catalog.
type AGHSyncConfig struct {
	Enabled         bool        `toml:"enabled" reload:"safe"`
	BaseURL         string      `toml:"base_url" reload:"safe"`
	EnvFile         string      `toml:"env_file" reload:"safe"`
	SyncInterval    string      `toml:"sync_interval" reload:"safe"`
	SyncFilters     bool        `toml:"sync_filters" reload:"safe"`
	SyncCustomRules bool        `toml:"sync_custom_rules" reload:"safe"`
	SyncAllowDeny   bool        `toml:"sync_allow_deny" reload:"safe"`
	SyncQueryLog    bool        `toml:"sync_query_log" reload:"safe"`
	FilterURLs      []string    `toml:"filter_urls" reload:"safe"`
	CustomRules     []string    `toml:"custom_rules" reload:"safe"`
	CNAME           CNAMEConfig `toml:"cname" reload:"safe"`
}

// AGHManagedConfig controls the managed rewrite feed that AdGuard Home can
// subscribe to as a normal DNS blocklist/filter list.
type AGHManagedConfig struct {
	Enabled                           bool                `toml:"enabled" reload:"safe"`
	FeedPath                          string              `toml:"feed_path" reload:"safe"`
	TargetName                        string              `toml:"target_name" reload:"safe"`
	TargetMode                        string              `toml:"target_mode" reload:"safe"` // resolved_ip|cname|static_ip
	StaticIPv4                        []string            `toml:"static_ipv4" reload:"safe"`
	StaticIPv6                        []string            `toml:"static_ipv6" reload:"safe"`
	EmergencyEmpty                    bool                `toml:"emergency_empty" reload:"safe"`
	AutoEmergencyEmptyOnTargetFailure bool                `toml:"auto_emergency_empty_on_target_failure" reload:"safe"`
	DefaultPreset                     string              `toml:"default_preset" reload:"safe"` // conservative|balanced|aggressive
	StaleTargetTTL                    string              `toml:"stale_target_ttl" reload:"safe"`
	Scheduler                         AGHManagedScheduler `toml:"scheduler" reload:"safe"`
}

// AGHManagedScheduler controls periodic import of managed rewrite sources.
type AGHManagedScheduler struct {
	Enabled                     bool   `toml:"enabled" reload:"safe"`
	DefaultSyncInterval         string `toml:"default_sync_interval" reload:"safe"`
	SyncTimeout                 string `toml:"sync_timeout" reload:"safe"`
	MaxParallelSyncs            int    `toml:"max_parallel_syncs" reload:"safe"`
	Jitter                      string `toml:"jitter" reload:"safe"`
	StaleSourceTTL              string `toml:"stale_source_ttl" reload:"safe"`
	LargeChangeThresholdPercent int    `toml:"large_change_threshold_percent" reload:"safe"`
	LargeChangeThresholdCount   int    `toml:"large_change_threshold_count" reload:"safe"`
	LargeChangeRequiresReview   bool   `toml:"large_change_requires_review" reload:"safe"`
}

// CNAMEConfig controls CNAME cloaking candidate metadata sync.
type CNAMEConfig struct {
	Enabled                bool     `toml:"enabled" reload:"safe"`
	UseQueryLog            bool     `toml:"use_query_log" reload:"safe"`
	KnownTrackerSources    []string `toml:"known_tracker_sources" reload:"safe"`
	CandidateMinConfidence string   `toml:"candidate_min_confidence" reload:"safe"`
}

// RuleCatalogConfig controls the metadata catalog separate from HTTP responses.
type RuleCatalogConfig struct {
	Path            string `toml:"path" reload:"safe"`
	RefreshOnReload bool   `toml:"refresh_on_reload" reload:"safe"`
}

// UnknownProfileConfig controls fallback behavior only for unmatched URLs.
type UnknownProfileConfig struct {
	Enabled    bool                  `toml:"enabled" reload:"safe"`
	Default    string                `toml:"default" reload:"safe"` // safe|balanced|aggressive
	Safe       UnknownProfileActions `toml:"safe" reload:"safe"`
	Balanced   UnknownProfileActions `toml:"balanced" reload:"safe"`
	Aggressive UnknownProfileActions `toml:"aggressive" reload:"safe"`
}

// UnknownProfileActions maps resource classes to fallback directives.
type UnknownProfileActions struct {
	SuspiciousDomain string `toml:"suspicious_domain" reload:"safe"`
	TrackingPixel    string `toml:"tracking_pixel" reload:"safe"`
	Beacon           string `toml:"beacon" reload:"safe"`
	Javascript       string `toml:"javascript" reload:"safe"`
	APIJSON          string `toml:"api_json" reload:"safe"`
}

// Defaults returns a Config with production-sane defaults. Initial defaults enable
// full functionality; constrained VMs pare back via the sample config.
func Defaults() Config {
	return Config{
		Version: SchemaVersion,
		Listen:  ListenConfig{HTTP: ":80", HTTPS: ":443", IPv6: true},
		// Design doc C-2: quic default OFF (block UDP443, force TCP) for
		// constrained VMs; termination/passthrough are opt-in.
		Protocols: ProtocolsConfig{HTTP1: true, HTTP2: true, QUIC: false, HTTP3: false},
		Cert: CertConfig{
			IntermediateCert: "/etc/mirage-chaff/ca/intermediate.crt",
			IntermediateKey:  "/etc/mirage-chaff/ca/intermediate.key",
			KeyType:          "ecdsa",
			CacheMax:         2048,
			CacheTTLHours:    168,
			CacheDir:         "/var/lib/mirage-chaff/certcache",
		},
		Upstream:  UpstreamConfig{Resolvers: []string{"https://1.1.1.1/dns-query"}},
		Mode:      "full",
		Mimic:     MimicConfig{Enabled: true, MaxBytes: 8 << 20, CacheMax: 512, AllowVideo: false},
		Resources: ResourcesConfig{MaxConns: 1024, RateLimit: 0, BodyMaxBytes: 32 << 20},
		Log:       LogConfig{Level: "info", Mode: "redacted", Retention: "7d", Redact: true},
		Observability: ObservabilityConfig{
			Listen: "127.0.0.1:9256", Metrics: true,
			Catalog: ObservabilityCatalogConfig{
				Enabled: true, PrometheusLabels: []string{"category", "risk", "verified", "review_status", "source_type"},
				EmitSIEMCatalogFields: true,
			},
		},
		Admin: AdminConfig{Enabled: false, Listen: "127.0.0.1:8443", SecureCookies: false},
		Paths: PathsConfig{
			PolicyDir:  "/etc/mirage-chaff/policy.d",
			CatalogDir: "/etc/mirage-chaff/catalog",
			StateDir:   "/var/lib/mirage-chaff",
			AGHEnv:     "/etc/mirage-chaff/agh.env",
		},
		AGHSync: AGHSyncConfig{
			Enabled: false, BaseURL: "http://127.0.0.1:3000", EnvFile: "/etc/mirage-chaff/agh.env",
			SyncInterval: "1h", SyncFilters: true, SyncCustomRules: true, SyncAllowDeny: true,
			CNAME: CNAMEConfig{Enabled: true, UseQueryLog: true, KnownTrackerSources: []string{"rule_catalog"}, CandidateMinConfidence: "medium"},
		},
		AGHManaged: AGHManagedConfig{
			Enabled: false, FeedPath: "/agh/managed-rewrites.txt", TargetName: "mirage-chaff.lan",
			TargetMode: "resolved_ip", DefaultPreset: "balanced", StaleTargetTTL: "24h",
			Scheduler: AGHManagedScheduler{
				Enabled: true, DefaultSyncInterval: "12h", SyncTimeout: "30s", MaxParallelSyncs: 2,
				Jitter: "10m", StaleSourceTTL: "72h", LargeChangeThresholdPercent: 25,
				LargeChangeThresholdCount: 500, LargeChangeRequiresReview: true,
			},
		},
		RuleCatalog: RuleCatalogConfig{Path: "/var/lib/mirage-chaff/rule-catalog.json", RefreshOnReload: true},
		UnknownProfile: UnknownProfileConfig{
			Enabled: true, Default: "safe",
			Safe:       UnknownProfileActions{SuspiciousDomain: "observe", TrackingPixel: "forward", Beacon: "forward", Javascript: "forward", APIJSON: "forward"},
			Balanced:   UnknownProfileActions{SuspiciousDomain: "observe", TrackingPixel: "stub:pixel", Beacon: "stub:beacon-204", Javascript: "forward", APIJSON: "forward"},
			Aggressive: UnknownProfileActions{SuspiciousDomain: "stub:beacon-204", TrackingPixel: "stub:pixel", Beacon: "stub:beacon-204", Javascript: "candidate-log", APIJSON: "forward"},
		},
	}
}

// Load reads the config file and returns a resolved Config: it starts from
// Defaults() and decodes the TOML at path over them, so any field omitted in the
// file keeps its default. If the file is absent, the defaults are returned (so
// the binary runs out of the box for local testing).
func Load(path string) (Config, error) {
	cfg := Defaults()
	cfg.path = path

	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Path returns the file this config was loaded from ("" if defaults-only).
func (c Config) Path() string { return c.path }

// Check validates the resolved config. It is used by `mirage-chaff check`
// (D-1) and before every reload/start so a bad config never brings the service
// down silently.
func (c Config) Check() error {
	if c.Version > SchemaVersion {
		// D-3: forward-compat — warn, do not fail.
		fmt.Fprintf(os.Stderr, "warning: config version %d is newer than supported %d; interpreting known fields only\n", c.Version, SchemaVersion)
	}
	switch c.Mode {
	case "full", "stub-only":
	default:
		return fmt.Errorf("mode: must be \"full\" or \"stub-only\", got %q", c.Mode)
	}
	switch c.Cert.KeyType {
	case "ecdsa", "rsa":
	default:
		return fmt.Errorf("cert.key_type: must be \"ecdsa\" or \"rsa\", got %q", c.Cert.KeyType)
	}
	// HTTP/3 requires QUIC transport (design doc protocol layering).
	if c.Protocols.HTTP3 && !c.Protocols.QUIC {
		return errors.New("protocols.http3 requires protocols.quic = true")
	}
	if c.Listen.HTTPS == "" {
		return errors.New("listen.https must be set")
	}
	if len(c.Upstream.Resolvers) == 0 {
		return errors.New("upstream.resolvers must not be empty (must NOT point at AdGuard Home)")
	}
	switch c.Log.Mode {
	case "", "off", "redacted", "stats", "debug", "full":
	default:
		return fmt.Errorf("log.mode: must be off|redacted|stats|debug|full, got %q", c.Log.Mode)
	}
	switch c.UnknownProfile.Default {
	case "", "safe", "balanced", "aggressive":
	default:
		return fmt.Errorf("unknown_profile.default: must be safe|balanced|aggressive, got %q", c.UnknownProfile.Default)
	}
	if c.RuleCatalog.Path == "" {
		return errors.New("rule_catalog.path must be set")
	}
	if c.AGHManaged.FeedPath == "" {
		return errors.New("agh_managed_rewrites.feed_path must be set")
	}
	switch c.AGHManaged.TargetMode {
	case "", "resolved_ip", "cname", "static_ip":
	default:
		return fmt.Errorf("agh_managed_rewrites.target_mode: must be resolved_ip|cname|static_ip, got %q", c.AGHManaged.TargetMode)
	}
	switch c.AGHManaged.DefaultPreset {
	case "", "conservative", "balanced", "aggressive":
	default:
		return fmt.Errorf("agh_managed_rewrites.default_preset: must be conservative|balanced|aggressive, got %q", c.AGHManaged.DefaultPreset)
	}
	if c.Observability.Listen == "" {
		// A-3: health/metrics must be independent of admin and always available.
		return errors.New("observability.listen must be set (health/metrics must stay up even when admin is disabled)")
	}
	return nil
}
