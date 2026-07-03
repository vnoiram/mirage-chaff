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

	Listen        ListenConfig        `toml:"listen"`
	Protocols     ProtocolsConfig     `toml:"protocols"`
	Cert          CertConfig          `toml:"cert"`
	Upstream      UpstreamConfig      `toml:"upstream"`
	Mode          string              `toml:"mode" reload:"safe"` // "full" | "stub-only"
	Mimic         MimicConfig         `toml:"mimic"`
	Resources     ResourcesConfig     `toml:"resources"`
	Log           LogConfig           `toml:"log" reload:"safe"`
	Observability ObservabilityConfig `toml:"observability"`
	Admin         AdminConfig         `toml:"admin"`
	Paths         PathsConfig         `toml:"paths"`

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

// MimicConfig controls forward-mimic (shape-preserving decoys). Phase 4 scope is
// image/js/binary only; video is deferred (design doc C-1).
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
	Level  string `toml:"level" reload:"safe"`  // "debug"|"info"|"warn"|"error"
	Redact bool   `toml:"redact" reload:"safe"` // mask sensitive URL/query/header values
}

// ObservabilityConfig is the admin-INDEPENDENT health/metrics listener (A-3).
// It must keep serving /-/healthy, /ready (and optionally /metrics) even when
// Admin.Enabled is false, so systemd watchdog + Uptime Kuma + Prometheus survive.
type ObservabilityConfig struct {
	Listen  string `toml:"listen" reload:"restart"` // e.g. "127.0.0.1:9256"
	Metrics bool   `toml:"metrics" reload:"restart"`
}

// AdminConfig controls the web admin UI (MITM control plane; localhost default).
type AdminConfig struct {
	Enabled bool       `toml:"enabled" reload:"restart"`
	Listen  string     `toml:"listen" reload:"restart"` // e.g. "127.0.0.1:8443"
	OIDC    OIDCConfig `toml:"oidc"`
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
		Upstream:      UpstreamConfig{Resolvers: []string{"https://1.1.1.1/dns-query"}},
		Mode:          "full",
		Mimic:         MimicConfig{Enabled: true, MaxBytes: 8 << 20, CacheMax: 512, AllowVideo: false},
		Resources:     ResourcesConfig{MaxConns: 1024, RateLimit: 0, BodyMaxBytes: 32 << 20},
		Log:           LogConfig{Level: "info", Redact: true},
		Observability: ObservabilityConfig{Listen: "127.0.0.1:9256", Metrics: true},
		Admin:         AdminConfig{Enabled: false, Listen: "127.0.0.1:8443"},
		Paths: PathsConfig{
			PolicyDir:  "/etc/mirage-chaff/policy.d",
			CatalogDir: "/etc/mirage-chaff/catalog",
			StateDir:   "/var/lib/mirage-chaff",
			AGHEnv:     "/etc/mirage-chaff/agh.env",
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
	if c.Observability.Listen == "" {
		// A-3: health/metrics must be independent of admin and always available.
		return errors.New("observability.listen must be set (health/metrics must stay up even when admin is disabled)")
	}
	return nil
}
