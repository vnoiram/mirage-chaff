// Package server wires the process lifecycle together: it loads the intermediate
// CA (certgen) and catalog, starts the admin-independent health/metrics listener,
// binds the :80/:443 intercept listeners, terminates TLS with per-SNI dynamic
// leaves, routes requests to an action (Phase 1: stub), handles SIGHUP for
// validate-then-swap reload of the catalog (design doc D-2), and drains
// gracefully on shutdown.
//
// The policy engine (Phase 2) replaces the fixed default-stub routing.
package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/catalog"
	"github.com/vnoiram/mirage-chaff/internal/certgen"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/observability"
	"github.com/vnoiram/mirage-chaff/internal/stub"
)

// defaultStubEntry is served for every intercepted request until the policy
// engine (Phase 2) selects per-domain actions.
const defaultStubEntry = "beacon-204"

// Server owns the running process.
type Server struct {
	cfg     config.Config
	version string
	cfgPath string
	health  *observability.Health
	issuer  *certgen.Issuer

	cat atomic.Pointer[catalog.Catalog]
}

// New constructs a Server.
func New(cfg config.Config, version, cfgPath string) *Server {
	return &Server{cfg: cfg, version: version, cfgPath: cfgPath, health: &observability.Health{}}
}

// Run starts the server and blocks until ctx is cancelled (SIGTERM/SIGINT).
func (s *Server) Run(ctx context.Context) error {
	log.Printf("mirage-chaff %s starting (config=%q)", s.version, displayPath(s.cfgPath))

	// Load catalog (fail fast — a broken catalog must not start).
	cat, err := catalog.Load(s.cfg.Paths.CatalogDir)
	if err != nil {
		return err
	}
	s.cat.Store(cat)
	log.Printf("catalog loaded: %d entries from %s", len(cat.Names()), s.cfg.Paths.CatalogDir)

	// Load intermediate CA. If it is missing, run without TLS interception so
	// health/monitoring still work before CA setup (logged prominently).
	if iss, err := certgen.NewIssuer(s.cfg.Cert); err != nil {
		log.Printf("WARNING: TLS interception disabled — intermediate CA not usable: %v", err)
	} else {
		s.issuer = iss
		log.Printf("intermediate CA loaded (fingerprint %s…, key_type=%s)", iss.Fingerprint()[:16], s.cfg.Cert.KeyType)
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	var wg sync.WaitGroup
	fatal := make(chan error, 4)

	// Health/metrics — independent of admin (A-3).
	obs := observability.New(s.cfg.Observability.Listen, s.cfg.Observability.Metrics, s.health)
	wg.Add(1)
	go func() { defer wg.Done(); fatal <- obs.Start(ctx) }()
	log.Printf("health/metrics listening on %s (independent of admin.enabled=%v)",
		s.cfg.Observability.Listen, s.cfg.Admin.Enabled)

	handler := http.HandlerFunc(s.handleIntercept)
	var servers []*http.Server

	// :80 plaintext HTTP/1.1.
	if s.cfg.Protocols.HTTP1 && s.cfg.Listen.HTTP != "" {
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		if err := s.serve(ctx, &wg, fatal, srv, s.cfg.Listen.HTTP, false); err != nil {
			return err
		}
		log.Printf("intercept HTTP listening on %s", s.cfg.Listen.HTTP)
	}

	// :443 TLS (HTTP/1.1 + optional h2 via ALPN).
	if s.issuer != nil && s.cfg.Listen.HTTPS != "" {
		srv := &http.Server{
			Handler:           handler,
			TLSConfig:         s.issuer.TLSConfig(s.alpn()),
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, srv)
		if err := s.serve(ctx, &wg, fatal, srv, s.cfg.Listen.HTTPS, true); err != nil {
			return err
		}
		log.Printf("intercept HTTPS listening on %s (alpn=%v)", s.cfg.Listen.HTTPS, s.alpn())
	}

	s.health.SetReady(true)
	log.Printf("ready (mode=%s, quic=%v, http3=%v)", s.cfg.Mode, s.cfg.Protocols.QUIC, s.cfg.Protocols.HTTP3)

	// Lifecycle loop.
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown signal received; draining")
			s.health.SetReady(false)
			s.shutdown(servers)
			wg.Wait()
			return nil
		case <-hup:
			s.reload()
		case err := <-fatal:
			if err != nil {
				log.Printf("listener failed: %v", err)
				s.health.SetReady(false)
				s.shutdown(servers)
				wg.Wait()
				return err
			}
		}
	}
}

// serve binds addr and serves srv, reporting a bind failure synchronously.
func (s *Server) serve(ctx context.Context, wg *sync.WaitGroup, fatal chan<- error, srv *http.Server, addr string, tlsMode bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var e error
		if tlsMode {
			// GetCertificate is set on srv.TLSConfig; empty cert/key files are fine
			// and this path auto-configures HTTP/2 from the ALPN list.
			e = srv.ServeTLS(ln, "", "")
		} else {
			e = srv.Serve(ln)
		}
		if e != nil && !errors.Is(e, http.ErrServerClosed) {
			fatal <- e
		}
	}()
	return nil
}

func (s *Server) shutdown(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
}

func (s *Server) alpn() []string {
	var a []string
	if s.cfg.Protocols.HTTP2 {
		a = append(a, "h2")
	}
	if s.cfg.Protocols.HTTP1 {
		a = append(a, "http/1.1")
	}
	if len(a) == 0 {
		a = []string{"http/1.1"}
	}
	return a
}

// handleIntercept routes a decrypted request. Phase 1: everything gets the
// default stub decoy. Phase 2 swaps in the policy engine.
func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	stub.Serve(w, r, s.cat.Load(), defaultStubEntry)
}

// reload re-reads config + catalog and swaps reload-safe state. Validate-then-swap
// (D-2): on any error the current state is kept.
func (s *Server) reload() {
	log.Printf("SIGHUP: reloading config + catalog")
	newCfg, err := config.Load(s.cfgPath)
	if err != nil {
		log.Printf("reload aborted: config load failed, keeping current: %v", err)
		return
	}
	if err := newCfg.Check(); err != nil {
		log.Printf("reload aborted: config invalid, keeping current: %v", err)
		return
	}
	newCat, err := catalog.Load(newCfg.Paths.CatalogDir)
	if err != nil {
		log.Printf("reload aborted: catalog invalid, keeping current: %v", err)
		return
	}
	s.cat.Store(newCat)
	s.cfg.Mode = newCfg.Mode
	s.cfg.Log = newCfg.Log
	s.cfg.Mimic = newCfg.Mimic
	log.Printf("reload complete: %d catalog entries", len(newCat.Names()))
}

func displayPath(p string) string {
	if p == "" {
		return "(defaults)"
	}
	return p
}
