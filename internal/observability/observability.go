// Package observability provides structured logging, metrics, and the health
// endpoints — served on a listener that is INDEPENDENT of the admin UI.
//
// Design doc A-3: /-/healthy, /ready and /metrics must keep responding even when
// admin.enabled = false, otherwise the systemd watchdog, Uptime Kuma/Blackbox
// probes, and Prometheus scrape all break when admin is turned off on a
// constrained VM. This listener is therefore owned here, not by internal/admin.
package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Health tracks readiness so /ready can gate on the data path being up.
type Health struct {
	ready atomic.Bool
}

// SetReady marks the service ready (data-path listeners bound) or not.
func (h *Health) SetReady(v bool) { h.ready.Store(v) }

// Server is the admin-independent health/metrics HTTP listener.
type Server struct {
	addr       string
	metricsOn  bool
	health     *Health
	rec        *Recorder
	extra      func(*strings.Builder)
	httpServer *http.Server
}

// SetExtraMetrics registers a callback that appends additional Prometheus lines
// (e.g. server-level gauges) to /metrics. Must be set before Start.
func (s *Server) SetExtraMetrics(f func(*strings.Builder)) { s.extra = f }

// New builds the observability server. addr is e.g. "127.0.0.1:9256". rec may be
// nil (then /metrics reports only the up gauge).
func New(addr string, metricsOn bool, h *Health, rec *Recorder) *Server {
	return &Server{addr: addr, metricsOn: metricsOn, health: h, rec: rec}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	// Liveness: process is up.
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "healthy")
	})
	// Readiness: data-path bound and serving.
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if s.health != nil && !s.health.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})

	if s.metricsOn {
		// Phase 7 wires real Prometheus metrics; Phase 0 exposes a stub so the
		// scrape target and Blackbox probe have something to hit.
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			var sb strings.Builder
			sb.WriteString("# HELP mirage_chaff_up 1 if the server is up.\n")
			sb.WriteString("# TYPE mirage_chaff_up gauge\n")
			sb.WriteString("mirage_chaff_up 1\n")
			if s.rec != nil {
				s.rec.WriteMetrics(&sb)
			}
			if s.extra != nil {
				s.extra(&sb)
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = io.WriteString(w, sb.String())
		})
	}
	return mux
}

// Start binds and serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("observability listen %s: %w", s.addr, err)
	}
	s.httpServer = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second}

	errCh := make(chan error, 1)
	go func() { errCh <- s.httpServer.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
