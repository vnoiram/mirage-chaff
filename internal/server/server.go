// Package server wires the process lifecycle together: it starts the
// admin-independent health/metrics listener, will own the :80/:443 (and optional
// UDP443) intercept listeners from Phase 1 onward, handles SIGHUP for
// validate-then-swap reload of policy.d/catalog (design doc D-2), and performs a
// graceful drain on shutdown.
//
// Phase 0 implements the lifecycle scaffold: health listener + signal handling +
// reload hook. The TLS intercept data path lands in Phase 1.
package server

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/observability"
)

// Server owns the running process.
type Server struct {
	cfg     config.Config
	version string
	cfgPath string
	health  *observability.Health
}

// New constructs a Server. cfgPath is retained so SIGHUP can re-read config.
func New(cfg config.Config, version, cfgPath string) *Server {
	return &Server{cfg: cfg, version: version, cfgPath: cfgPath, health: &observability.Health{}}
}

// Run starts the server and blocks until ctx is cancelled (SIGTERM/SIGINT).
func (s *Server) Run(ctx context.Context) error {
	log.Printf("mirage-chaff %s starting (config=%q)", s.version, displayPath(s.cfgPath))

	// SIGHUP -> hot reload of policy.d/catalog (reload-safe fields only).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	obs := observability.New(s.cfg.Observability.Listen, s.cfg.Observability.Metrics, s.health)
	obsErr := make(chan error, 1)
	go func() { obsErr <- obs.Start(ctx) }()
	log.Printf("health/metrics listening on %s (independent of admin.enabled=%v)",
		s.cfg.Observability.Listen, s.cfg.Admin.Enabled)

	// TODO(Phase 1+): bind :80/:443 intercept listeners, load certgen intermediate
	// CA, load policy engine + catalog, then mark ready.
	s.health.SetReady(true)
	log.Printf("ready (mode=%s, quic=%v, http3=%v)", s.cfg.Mode, s.cfg.Protocols.QUIC, s.cfg.Protocols.HTTP3)

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown signal received; draining")
			s.health.SetReady(false)
			return <-obsErr
		case <-hup:
			s.reload()
		case err := <-obsErr:
			return err
		}
	}
}

// reload re-reads and validates config, then swaps reload-safe state. Following
// D-2 (validate-then-swap): if the new config is invalid, the old state is kept.
func (s *Server) reload() {
	log.Printf("SIGHUP: reloading policy.d/catalog")
	newCfg, err := config.Load(s.cfgPath)
	if err != nil {
		log.Printf("reload aborted: config load failed, keeping current config: %v", err)
		return
	}
	if err := newCfg.Check(); err != nil {
		log.Printf("reload aborted: config invalid, keeping current config: %v", err)
		return
	}
	// TODO(Phase 2+): re-load policy.d + catalog into a fresh ruleset and swap
	// atomically; restart-required fields are ignored here by design.
	s.cfg.Mode = newCfg.Mode
	s.cfg.Log = newCfg.Log
	s.cfg.Mimic = newCfg.Mimic
	log.Printf("reload complete")
}

func displayPath(p string) string {
	if p == "" {
		return "(defaults)"
	}
	return p
}
