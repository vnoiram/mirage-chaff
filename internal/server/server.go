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
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/netutil"

	"github.com/vnoiram/mirage-chaff/internal/admin"
	"github.com/vnoiram/mirage-chaff/internal/catalog"
	"github.com/vnoiram/mirage-chaff/internal/certgen"
	"github.com/vnoiram/mirage-chaff/internal/config"
	"github.com/vnoiram/mirage-chaff/internal/forward"
	"github.com/vnoiram/mirage-chaff/internal/hashrewrite"
	"github.com/vnoiram/mirage-chaff/internal/mimic"
	"github.com/vnoiram/mirage-chaff/internal/observability"
	"github.com/vnoiram/mirage-chaff/internal/passthrough"
	"github.com/vnoiram/mirage-chaff/internal/policy"
	quicpkg "github.com/vnoiram/mirage-chaff/internal/quic"
	"github.com/vnoiram/mirage-chaff/internal/resolver"
	"github.com/vnoiram/mirage-chaff/internal/sdnotify"
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

	breaker *breaker
	limiter atomic.Pointer[rateLimiter]

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
	s.mimic.Store(mimic.New(res, mimic.Options{MaxBytes: s.cfg.Mimic.MaxBytes, AllowVideo: s.cfg.Mimic.AllowVideo, CacheMax: s.cfg.Mimic.CacheMax}))
	s.fwd.Store(forward.New(res, forward.Options{OnError: s.forwardFailSafe, BodyModifier: s.rewriteHashes}))
	s.recorder = observability.NewRecorder(s.cfg.Log.Redact, 4096)
	s.breaker = newBreaker(5, 30*time.Second)
	s.limiter.Store(newRateLimiter(s.cfg.Resources.RateLimit))

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
	obs.SetExtraMetrics(s.extraMetrics)
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
		if err := s.serve(ctx, &wg, fatal, srv, s.cfg.Listen.HTTP, true); err != nil {
			return err
		}
		log.Printf("intercept HTTP listening on %s", s.cfg.Listen.HTTP)
	}

	// :443 TLS. A routing listener peeks the SNI before TLS termination and
	// splices passthrough domains straight to the origin (design doc
	// tcp-passthrough); everything else is TLS-terminated and served as HTTP.
	if s.issuer != nil && s.cfg.Listen.HTTPS != "" {
		ln, err := s.limitedListen(s.cfg.Listen.HTTPS)
		if err != nil {
			return err
		}
		routed := newRoutingListener(ln, s)
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

	// UDP443 QUIC: terminate HTTP/3, passthrough-relay, or leave closed (firewall
	// blocks it) per protocols.quic/http3 (design doc C-2 layering).
	var quicCloser func()
	if s.cfg.Protocols.QUIC && s.issuer != nil && s.cfg.Listen.HTTPS != "" {
		var err error
		quicCloser, err = s.startQUIC(&wg, fatal, handler)
		if err != nil {
			return err
		}
	} else if s.cfg.Protocols.QUIC {
		log.Printf("protocols.quic set but no CA/listener; UDP443 not opened")
	}

	// Admin UI (optional; MITM control plane). Health/metrics stay independent.
	if s.cfg.Admin.Enabled {
		if err := s.startAdmin(ctx, &wg, fatal, &servers); err != nil {
			return err
		}
	}

	s.health.SetReady(true)
	_ = sdnotify.Ready()
	watchdogStop := make(chan struct{})
	go sdnotify.RunWatchdog(watchdogStop)
	log.Printf("ready (mode=%s, quic=%v, http3=%v)", s.cfg.Mode, s.cfg.Protocols.QUIC, s.cfg.Protocols.HTTP3)

	// Lifecycle loop.
	drain := func() {
		s.health.SetReady(false)
		_ = sdnotify.Stopping()
		close(watchdogStop)
		if quicCloser != nil {
			quicCloser()
		}
		s.shutdown(servers)
		wg.Wait()
	}
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutdown signal received; draining")
			drain()
			return nil
		case <-hup:
			s.reload()
		case err := <-fatal:
			if err != nil {
				log.Printf("listener failed: %v", err)
				drain()
				return err
			}
		}
	}
}

// startAdmin builds and serves the admin UI, wiring it to server state via Deps.
func (s *Server) startAdmin(ctx context.Context, wg *sync.WaitGroup, fatal chan<- error, servers *[]*http.Server) error {
	store, err := admin.OpenStore(filepath.Join(s.cfg.Paths.StateDir, "admin", "admin.json"))
	if err != nil {
		return err
	}
	a := admin.New(store, admin.Deps{
		Version:    s.version,
		ConfigPath: s.cfgPath,
		Paths:      s.cfg.Paths,
		Recorder:   s.recorder,
		Engine:     s.engine,
		CertFingerprint: func() string {
			if s.issuer != nil {
				return s.issuer.Fingerprint()
			}
			return ""
		},
		CertKeyType: s.cfg.Cert.KeyType,
		Reload:      func() error { return syscall.Kill(os.Getpid(), syscall.SIGHUP) },
		KillSwitch:  s.runKillSwitch,
		Listeners:   s.listenersInfo,
		OIDC:        s.cfg.Admin.OIDC,
	})
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	*servers = append(*servers, srv)
	if err := s.serve(ctx, wg, fatal, srv, s.cfg.Admin.Listen, false); err != nil {
		return err
	}
	log.Printf("admin UI listening on %s (RBAC; localhost by default)", s.cfg.Admin.Listen)
	return nil
}

// runKillSwitch executes the kill-switch script (design doc A-4). Its path comes
// from MC_KILLSWITCH or the default install location.
func (s *Server) runKillSwitch() error {
	path := os.Getenv("MC_KILLSWITCH")
	if path == "" {
		path = "/usr/local/bin/mirage-chaff-killswitch"
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("kill-switch script not found at %s (set MC_KILLSWITCH)", path)
	}
	out, err := exec.Command("/bin/sh", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// extraMetrics appends server-level gauges to /metrics (Phase 7 Prometheus).
func (s *Server) extraMetrics(sb *strings.Builder) {
	rs := s.engine.Ruleset()
	sb.WriteString("# HELP mirage_chaff_policy_rules Loaded policy rules.\n")
	sb.WriteString("# TYPE mirage_chaff_policy_rules gauge\n")
	fmt.Fprintf(sb, "mirage_chaff_policy_rules %d\n", len(rs.Rules()))

	sb.WriteString("# HELP mirage_chaff_temp_allows Active temporary allow overrides.\n")
	sb.WriteString("# TYPE mirage_chaff_temp_allows gauge\n")
	fmt.Fprintf(sb, "mirage_chaff_temp_allows %d\n", len(s.engine.TempRules()))

	sb.WriteString("# HELP mirage_chaff_unmatched_domains Distinct unmatched domain/path pairs seen.\n")
	sb.WriteString("# TYPE mirage_chaff_unmatched_domains gauge\n")
	fmt.Fprintf(sb, "mirage_chaff_unmatched_domains %d\n", len(s.engine.UnmatchedTop(0)))

	if s.issuer != nil {
		sb.WriteString("# HELP mirage_chaff_intermediate_ca_not_after_seconds Intermediate CA expiry (unix seconds).\n")
		sb.WriteString("# TYPE mirage_chaff_intermediate_ca_not_after_seconds gauge\n")
		fmt.Fprintf(sb, "mirage_chaff_intermediate_ca_not_after_seconds %d\n", s.issuer.NotAfter().Unix())
	}
}

// listenersInfo reports the active listeners for the admin dashboard.
func (s *Server) listenersInfo() map[string]string {
	m := map[string]string{}
	if s.cfg.Protocols.HTTP1 && s.cfg.Listen.HTTP != "" {
		m["http"] = s.cfg.Listen.HTTP
	}
	if s.issuer != nil && s.cfg.Listen.HTTPS != "" {
		m["https"] = s.cfg.Listen.HTTPS
	}
	if s.cfg.Protocols.QUIC {
		if s.cfg.Protocols.HTTP3 {
			m["http3"] = s.cfg.Listen.HTTPS + " (udp)"
		} else {
			m["quic-passthrough"] = s.cfg.Listen.HTTPS + " (udp)"
		}
	}
	m["health"] = s.cfg.Observability.Listen
	return m
}

// startQUIC opens UDP443: HTTP/3 termination when protocols.http3, otherwise a
// QUIC passthrough relay. Returns a closer for graceful shutdown.
func (s *Server) startQUIC(wg *sync.WaitGroup, fatal chan<- error, handler http.Handler) (func(), error) {
	if s.cfg.Protocols.HTTP3 {
		h3, err := quicpkg.ListenHTTP3(s.cfg.Listen.HTTPS, s.issuer.GetCertificate, handler)
		if err != nil {
			return nil, err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := h3.Serve(); e != nil {
				select {
				case fatal <- e:
				default:
				}
			}
		}()
		log.Printf("HTTP/3 termination listening on UDP %s", s.cfg.Listen.HTTPS)
		return func() { _ = h3.Close() }, nil
	}

	relay, err := quicpkg.ListenPassthrough(s.cfg.Listen.HTTPS, "443", s.resolver)
	if err != nil {
		return nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if e := relay.Serve(); e != nil {
			select {
			case fatal <- e:
			default:
			}
		}
	}()
	log.Printf("QUIC passthrough relay listening on UDP %s", s.cfg.Listen.HTTPS)
	return func() { _ = relay.Close() }, nil
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

// limitedListen binds addr and, when resources.max_conns > 0, caps the number of
// simultaneously accepted connections (netutil.LimitListener) so a constrained VM
// cannot be exhausted by connection floods. Used for the intercept listeners; the
// health/admin listeners are left unlimited so they stay reachable under load.
func (s *Server) limitedListen(addr string) (net.Listener, error) {
	ln, err := s.listen(addr)
	if err != nil {
		return nil, err
	}
	if n := s.cfg.Resources.MaxConns; n > 0 {
		ln = netutil.LimitListener(ln, n)
	}
	return ln, nil
}

// serve binds addr and serves srv (plaintext), reporting a bind failure
// synchronously. When limit is set the listener honors resources.max_conns.
func (s *Server) serve(ctx context.Context, wg *sync.WaitGroup, fatal chan<- error, srv *http.Server, addr string, limit bool) error {
	var ln net.Listener
	var err error
	if limit {
		ln, err = s.limitedListen(addr)
	} else {
		ln, err = s.listen(addr)
	}
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
//
// The peek runs in a per-connection goroutine (not inline in Accept) so a single
// slow handshake cannot stall acceptance of every other new connection
// (slowloris resistance): a background acceptor feeds raw conns to peek workers,
// and terminated conns are delivered to Accept via a channel.
type routingListener struct {
	net.Listener
	s         *Server
	conns     chan net.Conn
	errs      chan error
	done      chan struct{}
	closeOnce sync.Once
}

func newRoutingListener(inner net.Listener, s *Server) *routingListener {
	l := &routingListener{
		Listener: inner,
		s:        s,
		conns:    make(chan net.Conn),
		errs:     make(chan error, 1),
		done:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

// acceptLoop pulls raw connections and hands each to a peek worker.
func (l *routingListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.errs <- err:
			case <-l.done:
			}
			return
		}
		go l.route(c)
	}
}

// route peeks the SNI: passthrough domains are spliced here, everything else is
// delivered to Accept for TLS termination.
func (l *routingListener) route(c net.Conn) {
	sni, replay, perr := passthrough.PeekClientHello(c)
	if perr == nil && sni != "" {
		if d := l.s.engine.Ruleset().Match(sni, "", ""); d.Action == policy.ActionPassthrough {
			l.s.doPassthrough(replay, sni)
			return
		}
	}
	select {
	case l.conns <- replay:
	case <-l.done:
		replay.Close()
	}
}

func (l *routingListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case err := <-l.errs:
		return nil, err
	}
}

// Close stops the acceptor and unblocks any pending peek workers.
func (l *routingListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
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
	// Resource guards (resources.rate_limit / resources.body_max_bytes).
	if !s.limiter.Load().Allow() {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if s.cfg.Resources.BodyMaxBytes > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Resources.BodyMaxBytes)
	}

	cat := s.cat.Load()
	domain := hostname(r)
	d := s.engine.Decide(domain, r.URL.Path, r.Method)

	// stub-only mode (design doc: safety mode that never contacts an upstream):
	// downgrade every non-stub action to a safe stub so no origin is reached.
	if gated, changed := stubOnlyGate(s.cfg.Mode, d); changed {
		s.noteOnce("stub-only:"+d.Action, d.Rule, "stub-only mode: serving safe stub instead of contacting upstream")
		d = gated
	}

	rw := &respRecorder{ResponseWriter: w, status: http.StatusOK}

	// Circuit breaker: if a domain's origin has been failing, serve a safe stub
	// directly instead of hammering it (only for actions that contact upstream).
	contactsUpstream := d.Action == policy.ActionForwardAsis ||
		d.Action == policy.ActionForwardScrubbed || d.Action == policy.ActionForwardMimic
	if contactsUpstream && !s.breaker.Allow(domain) {
		stub.Serve(rw, r, cat, safeDefaultStub)
		s.record(domain, r, d, rw)
		return
	}

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

	// Feed the breaker: forwardFailSafe marks rw.failed on upstream error.
	if contactsUpstream {
		if rw.failed {
			s.breaker.RecordFailure(domain)
		} else {
			s.breaker.RecordSuccess(domain)
		}
	}

	s.record(domain, r, d, rw)
}

// stubOnlyGate downgrades any non-stub decision to a safe stub when mode is
// "stub-only", so no upstream is contacted. changed reports whether it altered d.
func stubOnlyGate(mode string, d policy.Decision) (policy.Decision, bool) {
	if mode != "stub-only" || d.Action == policy.ActionStub {
		return d, false
	}
	d.Action = policy.ActionStub
	if d.Catalog == "" {
		d.Catalog = safeDefaultStub
	}
	return d, true
}

// record logs a redacted request summary via the recorder.
func (s *Server) record(domain string, r *http.Request, d policy.Decision, rw *respRecorder) {
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
	if rw, ok := w.(*respRecorder); ok {
		rw.failed = true
	}
	stub.Serve(w, r, s.cat.Load(), safeDefaultStub)
}

// respRecorder captures status and byte count for logging.
type respRecorder struct {
	http.ResponseWriter
	status      int
	n           int64
	wroteHeader bool
	failed      bool // set by forwardFailSafe on upstream error (feeds the breaker)
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

// hostname returns the request authority for policy matching: the request's own
// Host/:authority header when present, else the TLS SNI, with any port stripped.
// Matching on the request authority (not just the connection SNI) guards against
// HTTP/2 connection-coalescing misrouting — a reused connection can carry a
// request whose :authority differs from the SNI that opened it (design doc §A).
func hostname(r *http.Request) string {
	h := r.Host
	if h == "" && r.TLS != nil {
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

	// Resource guards: rate_limit and body_max_bytes apply live; max_conns only
	// affects newly-bound listeners (restart-required), so it is left in place.
	s.cfg.Resources.RateLimit = newCfg.Resources.RateLimit
	s.cfg.Resources.BodyMaxBytes = newCfg.Resources.BodyMaxBytes
	s.limiter.Store(newRateLimiter(newCfg.Resources.RateLimit))

	// Rebuild mimic (reload-safe thresholds: max_bytes/allow_video/mode).
	s.mimic.Store(mimic.New(s.resolver, mimic.Options{MaxBytes: newCfg.Mimic.MaxBytes, AllowVideo: newCfg.Mimic.AllowVideo, CacheMax: newCfg.Mimic.CacheMax}))

	// Rebuild the resolver/forwarder if the upstream resolver list changed
	// (reload-safe). Recorder redaction follows log.redact.
	if !equalStrings(s.cfg.Upstream.Resolvers, newCfg.Upstream.Resolvers) {
		if res, err := resolver.New(newCfg.Upstream.Resolvers); err != nil {
			log.Printf("reload: keeping current resolver (new one invalid: %v)", err)
		} else {
			s.resolver = res
			s.fwd.Store(forward.New(res, forward.Options{OnError: s.forwardFailSafe, BodyModifier: s.rewriteHashes}))
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
