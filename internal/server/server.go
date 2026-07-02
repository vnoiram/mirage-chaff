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
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vnoiram/mirage-chaff/internal/catalog"
	"github.com/vnoiram/mirage-chaff/internal/certgen"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/forward"
	"github.com/vnoiram/mirage-chaff/internal/hashrewrite"
	"github.com/vnoiram/mirage-chaff/internal/mimic"
	"github.com/vnoiram/mirage-chaff/internal/observability"
	"github.com/vnoiram/mirage-chaff/internal/passthrough"
	"github.com/vnoiram/mirage-chaff/internal/policy"
	"github.com/vnoiram/mirage-chaff/internal/resolver"
	"github.com/vnoiram/mirage-chaff/internal/stub"
)

// safeDefaultStub is served when a matched action is not yet implemented, so the
// request fails safe (no upstream contact) rather than breaking the page.
const safeDefaultStub = "beacon-204"

// Server owns the running process.
type Server struct {
	cfg      config.Config
	version  string
	cfgPath  string
	health   *observability.Health
	issuer   *certgen.Issuer
	engine   *policy.Engine
	resolver *resolver.Resolver
	recorder *observability.Recorder

	cat   atomic.Pointer[catalog.Catalog]
	fwd   atomic.Pointer[forward.Forwarder]
	mimic atomic.Pointer[mimic.Handler]
	once  sync.Map // action name -> logged "not implemented" once
}

// New constructs a Server.
func New(cfg config.Config, version, cfgPath string) *Server {
	return &Server{cfg: cfg, version: version, cfgPath: cfgPath, health: &observability.Health{}}
}

// Run starts the server and blocks until ctx is cancelled (SIGTERM/SIGINT).
func (s *Server) Run(ctx context.Context) error {
	log.Printf("mirage-chaff %s starting (config=%q)", s.version, displayPath(s.cfgPath))

	// Load catalog + policy (fail fast — broken config must not start).
	cat, err := catalog.Load(s.cfg.Paths.CatalogDir)
	if err != nil {
		return err
	}
	rs, err := policy.Load(s.cfg.Paths.PolicyDir)
	if err != nil {
		return err
	}
	if err := validateRefs(cat, rs); err != nil {
		return err
	}
	s.cat.Store(cat)
	s.engine = policy.NewEngine(rs)
	log.Printf("catalog loaded: %d entries; policy loaded: %d rules from %s",
		len(cat.Names()), len(rs.Rules()), s.cfg.Paths.PolicyDir)

	// Independent resolver + forwarder + mimic for forward/passthrough actions.
	res, err := resolver.New(s.cfg.Upstream.Resolvers)
	if err != nil {
		return err
	}
	s.resolver = res
	s.mimic.Store(mimic.New(res, mimic.Options{MaxBytes: s.cfg.Mimic.MaxBytes, AllowVideo: s.cfg.Mimic.AllowVideo}))
	s.fwd.Store(forward.New(res, forward.Options{OnError: s.forwardFailSafe, BodyModifier: s.rewriteHashes}))
	s.recorder = observability.NewRecorder(s.cfg.Log.Redact, 4096)

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
	obs := observability.New(s.cfg.Observability.Listen, s.cfg.Observability.Metrics, s.health, s.recorder)
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

	// :443 TLS. A routing listener peeks the SNI before TLS termination and
	// splices passthrough domains straight to the origin (design doc
	// tcp-passthrough); everything else is TLS-terminated and served as HTTP.
	if s.issuer != nil && s.cfg.Listen.HTTPS != "" {
		ln, err := s.listen(s.cfg.Listen.HTTPS)
		if err != nil {
			return err
		}
		routed := &routingListener{Listener: ln, s: s}
		srv := &http.Server{
			Handler:           handler,
			TLSConfig:         s.issuer.TLSConfig(s.alpn()),
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, srv)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := srv.ServeTLS(routed, "", ""); e != nil && !errors.Is(e, http.ErrServerClosed) {
				fatal <- e
			}
		}()
		log.Printf("intercept HTTPS listening on %s (alpn=%v, passthrough-aware)", s.cfg.Listen.HTTPS, s.alpn())
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

// listen binds addr. With ipv6 enabled it binds dual-stack ("tcp"); otherwise
// IPv4 only ("tcp4"), so a wildcard listener does not accidentally accept over
// IPv6 (design doc: close the IPv6 bypass under operator control).
func (s *Server) listen(addr string) (net.Listener, error) {
	network := "tcp"
	if !s.cfg.Listen.IPv6 {
		network = "tcp4"
	}
	return net.Listen(network, addr)
}

// serve binds addr and serves srv (plaintext), reporting a bind failure
// synchronously.
func (s *Server) serve(ctx context.Context, wg *sync.WaitGroup, fatal chan<- error, srv *http.Server, addr string, tlsMode bool) error {
	ln, err := s.listen(addr)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if e := srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			fatal <- e
		}
	}()
	return nil
}

// routingListener peeks the TLS SNI on each accepted connection. Passthrough
// domains are spliced to the origin here and never bubble up to TLS termination;
// all other connections are returned (with the ClientHello replayed) to ServeTLS.
type routingListener struct {
	net.Listener
	s *Server
}

func (l *routingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		sni, replay, perr := passthrough.PeekClientHello(c)
		if perr == nil && sni != "" {
			if d := l.s.engine.Ruleset().Match(sni, "", ""); d.Action == policy.ActionPassthrough {
				go l.s.doPassthrough(replay, sni)
				continue
			}
		}
		return replay, nil
	}
}

// doPassthrough splices a passthrough connection to the origin. The replayed
// ClientHello is fed to the origin via the copy loop, so the client's TLS
// session terminates at the real server (pinning preserved).
func (s *Server) doPassthrough(conn net.Conn, sni string) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := passthrough.Splice(ctx, conn, nil, sni, "443", s.resolver); err != nil {
		log.Printf("passthrough %s failed: %v", sni, err)
	}
	s.recorder.Log(observability.Record{
		Time: time.Now(), Domain: sni, Method: "CONNECT",
		Action: policy.ActionPassthrough, Status: 0,
	})
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

// handleIntercept routes a decrypted request through the policy engine, applies
// the matched action, and records a redacted summary.
func (s *Server) handleIntercept(w http.ResponseWriter, r *http.Request) {
	cat := s.cat.Load()
	domain := hostname(r)
	d := s.engine.Decide(domain, r.URL.Path, r.Method)
	rw := &respRecorder{ResponseWriter: w, status: http.StatusOK}

	switch d.Action {
	case policy.ActionStub:
		stub.Serve(rw, r, cat, d.Catalog)
	case policy.ActionForwardAsis:
		s.fwd.Load().Asis(rw, r)
	case policy.ActionForwardScrubbed:
		s.fwd.Load().Scrubbed(rw, r)
	case policy.ActionPassthrough:
		// Reached only when a passthrough rule is path-scoped (can't be decided
		// pre-termination). Closest no-modify behavior after termination is asis.
		s.noteOnce(d.Action, d.Rule, "serving forward-asis after termination")
		s.fwd.Load().Asis(rw, r)
	case policy.ActionForwardMimic:
		// Shape-preserving decoy (image/js/binary). Video/oversized fall back to a
		// safe stub (privacy default, design C-1).
		if !s.mimic.Load().Serve(rw, r) {
			s.noteOnce(d.Action, d.Rule, "mimic fell back to stub (unsupported/oversized media)")
			stub.Serve(rw, r, cat, safeDefaultStub)
		}
	default:
		stub.Serve(rw, r, cat, safeDefaultStub)
	}

	s.recorder.Log(observability.Record{
		Time:        time.Now(),
		Domain:      domain,
		Path:        r.URL.RequestURI(),
		Method:      r.Method,
		Action:      d.Action,
		Rule:        d.Rule,
		Status:      rw.status,
		Bytes:       rw.n,
		ContentType: rw.Header().Get("Content-Type"),
	})
}

func (s *Server) noteOnce(action, rule, msg string) {
	if _, loaded := s.once.LoadOrStore(action, true); !loaded {
		log.Printf("action %q (rule %q): %s", action, rule, msg)
	}
}

// rewriteHashes is the forward BodyModifier: for HTML/JSON manifests it rewrites
// SRI/integrity references whose target URL we have decoyed via mimic, so the
// integrity check passes against the decoy (design doc hashrewrite). References
// to URLs we have not decoyed are left untouched (forward-asis fallback, C-3).
func (s *Server) rewriteHashes(contentType string, body []byte) ([]byte, bool) {
	m := s.mimic.Load()
	hasher := func(src string) (string, bool) {
		key := src
		if u, err := url.Parse(src); err == nil {
			key = u.RequestURI()
		}
		if d, ok := m.Lookup(key); ok {
			return hashrewrite.Integrity(d.Hash), true
		}
		return "", false
	}
	out, n1 := hashrewrite.RewriteSRI(body, hasher)
	out, n2 := hashrewrite.RewriteJSONIntegrity(out, hasher)
	return out, n1+n2 > 0
}

// forwardFailSafe is the forward ErrorHandler: on upstream failure serve a safe
// decoy instead of a hard error, so a broken origin never fails worse than a
// block (design doc circuit-breaker spirit).
func (s *Server) forwardFailSafe(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("forward failed for %s%s: %v (serving safe stub)", hostname(r), r.URL.Path, err)
	stub.Serve(w, r, s.cat.Load(), safeDefaultStub)
}

// respRecorder captures status and byte count for logging.
type respRecorder struct {
	http.ResponseWriter
	status      int
	n           int64
	wroteHeader bool
}

func (rw *respRecorder) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *respRecorder) Write(p []byte) (int, error) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
	}
	n, err := rw.ResponseWriter.Write(p)
	rw.n += int64(n)
	return n, err
}

// Flush proxies http.Flusher so streaming responses still stream.
func (rw *respRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// hostname returns the request authority for policy matching: SNI when present
// (TLS), else the Host header, with any port stripped. Routing on authority/Host
// (not just SNI) guards against HTTP/2 coalescing misrouting (design doc §A).
func hostname(r *http.Request) string {
	h := r.Host
	if r.TLS != nil && r.TLS.ServerName != "" {
		h = r.TLS.ServerName
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// validateRefs ensures every catalog name referenced by the ruleset exists.
func validateRefs(cat *catalog.Catalog, rs *policy.Ruleset) error {
	for _, name := range rs.CatalogRefs() {
		if _, ok := cat.Get(name); !ok {
			return &refError{name}
		}
	}
	return nil
}

type refError struct{ name string }

func (e *refError) Error() string {
	return "policy references unknown catalog entry " + strconv.Quote(e.name)
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
	newRules, err := policy.Load(newCfg.Paths.PolicyDir)
	if err != nil {
		log.Printf("reload aborted: policy invalid, keeping current: %v", err)
		return
	}
	if err := validateRefs(newCat, newRules); err != nil {
		log.Printf("reload aborted: %v, keeping current", err)
		return
	}
	// Validated — swap both atomically.
	s.cat.Store(newCat)
	s.engine.Swap(newRules)
	s.cfg.Mode = newCfg.Mode
	s.cfg.Log = newCfg.Log
	s.cfg.Mimic = newCfg.Mimic

	// Rebuild mimic (reload-safe thresholds: max_bytes/allow_video/mode).
	s.mimic.Store(mimic.New(s.resolver, mimic.Options{MaxBytes: newCfg.Mimic.MaxBytes, AllowVideo: newCfg.Mimic.AllowVideo}))

	// Rebuild the resolver/forwarder if the upstream resolver list changed
	// (reload-safe). Recorder redaction follows log.redact.
	if !equalStrings(s.cfg.Upstream.Resolvers, newCfg.Upstream.Resolvers) {
		if res, err := resolver.New(newCfg.Upstream.Resolvers); err != nil {
			log.Printf("reload: keeping current resolver (new one invalid: %v)", err)
		} else {
			s.resolver = res
			s.fwd.Store(forward.New(res, forward.Options{OnError: s.forwardFailSafe}))
			s.cfg.Upstream = newCfg.Upstream
			log.Printf("reload: resolver updated")
		}
	}
	s.recorder.SetRedact(newCfg.Log.Redact)
	log.Printf("reload complete: %d catalog entries, %d rules", len(newCat.Names()), len(newRules.Rules()))
	s.logUnmatched()
}

// logUnmatched surfaces the top unmatched (domain, path) pairs as curation
// candidates. Triggered on reload so operators can pull the current list.
func (s *Server) logUnmatched() {
	top := s.engine.UnmatchedTop(10)
	if len(top) == 0 {
		return
	}
	log.Printf("curation candidates (top unmatched domains/paths):")
	for _, e := range top {
		log.Printf("  %6d  %s %s", e.Count, e.Domain, e.Path)
	}
}

func displayPath(p string) string {
	if p == "" {
		return "(defaults)"
	}
	return p
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
