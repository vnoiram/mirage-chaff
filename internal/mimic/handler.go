package mimic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a hostname to IPs via the independent resolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// Generation modes.
const (
	ModeDeterministic = "deterministic" // URL-seeded; stable bytes/hash across requests
	ModePerRequest    = "per-request"   // fresh bytes each request (stable within one response)
)

// CachedDecoy records what was served for a URL, so hashrewrite can look up the
// decoy hash for the same URL.
type CachedDecoy struct {
	Shape Shape
	Seed  string
	Hash  [32]byte
}

// Handler implements forward-mimic: probe the origin for shape, generate a
// deterministic decoy, and serve it (with Range support).
type Handler struct {
	client     *http.Client
	mode       string
	maxBytes   int64
	allowVideo bool

	mu       sync.Mutex
	cacheMax int
	cache    map[string]*cacheEntry // url string -> decoy (bounded, LRU)
}

type cacheEntry struct {
	decoy CachedDecoy
	used  time.Time
}

// Options tunes the Handler.
type Options struct {
	TLSClientConfig *tls.Config
	MaxBytes        int64
	Mode            string
	AllowVideo      bool
	// CacheMax bounds the URL->decoy lookup cache (LRU). <=0 uses a default, so a
	// long-running process cannot grow the cache without limit (one entry per
	// distinct decoyed URL otherwise).
	CacheMax int
}

// New builds a Handler probing origins through res.
func New(res Resolver, opts Options) *Handler {
	if opts.Mode == "" {
		opts.Mode = ModeDeterministic
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 8 << 20
	}
	if opts.CacheMax <= 0 {
		opts.CacheMax = 512
	}
	transport := &http.Transport{
		DialContext:         dialViaResolver(res),
		TLSClientConfig:     opts.TLSClientConfig,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &Handler{
		client:     &http.Client{Transport: transport, Timeout: 15 * time.Second},
		mode:       opts.Mode,
		maxBytes:   opts.MaxBytes,
		allowVideo: opts.AllowVideo,
		cacheMax:   opts.CacheMax,
		cache:      make(map[string]*cacheEntry),
	}
}

// Lookup returns the cached decoy for a URL, if one was served.
func (h *Handler) Lookup(url string) (CachedDecoy, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.cache[url]
	if !ok {
		return CachedDecoy{}, false
	}
	e.used = time.Now()
	return e.decoy, true
}

// storeDecoy records what was served for url, evicting the least-recently-used
// entry when over cacheMax.
func (h *Handler) storeDecoy(url string, d CachedDecoy) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[url] = &cacheEntry{decoy: d, used: time.Now()}
	for len(h.cache) > h.cacheMax {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range h.cache {
			if first || e.used.Before(oldest) {
				oldest, oldestKey, first = e.used, k, false
			}
		}
		delete(h.cache, oldestKey)
	}
}

// Serve mimics r's resource. It returns false (serving nothing) when the media
// is unsupported (video) or too large, so the caller falls back to stub/asis.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request) bool {
	urlKey := r.URL.String()

	// Reuse a previously-resolved shape when we have already decoyed this URL, so
	// we do not send a HEAD probe to the origin (a tracker) on every request —
	// this both cuts latency and avoids repeatedly contacting the very host the
	// privacy mode exists to avoid.
	var shape Shape
	if cached, ok := h.Lookup(urlKey); ok {
		shape = cached.Shape
	} else {
		media := ClassifyExt(r.URL.Path)
		shape = h.probe(r) // best-effort; fills content-type/length
		if media == "" {
			media = ClassifyContentType(shape.ContentType)
		}
		if media == MediaVideo && !h.allowVideo {
			return false
		}
		shape.Media = media
		if shape.ContentType == "" {
			shape.ContentType = defaultContentType(media, r.URL.Path)
		}
		if shape.Length <= 0 {
			shape.Length = defaultLength(media)
		}
	}
	if shape.Media == MediaVideo && !h.allowVideo {
		return false
	}
	if shape.Length > h.maxBytes {
		return false // too big; fall back (avoids heavy generation)
	}

	seed := urlKey
	if h.mode == ModePerRequest {
		var nonce [8]byte
		_, _ = rand.Read(nonce[:])
		seed = seed + "#" + hex.EncodeToString(nonce[:])
	}

	full, err := Generate(seed, shape)
	if err != nil {
		return false // e.g. ErrUnsupported
	}
	sum, _ := Hash(seed, shape)
	h.storeDecoy(urlKey, CachedDecoy{Shape: shape, Seed: seed, Hash: sum})

	h.write(w, r, shape, full)
	return true
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request, shape Shape, full []byte) {
	w.Header().Set("Content-Type", shape.ContentType)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Cache-Control", "no-store")

	if rng := r.Header.Get("Range"); rng != "" {
		if start, end, ok := parseRange(rng, int64(len(full))); ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(full)))
			w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			w.WriteHeader(http.StatusPartialContent)
			if r.Method != http.MethodHead {
				_, _ = w.Write(full[start : end+1])
			}
			return
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(full)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(full)
	}
}

// probe does a best-effort HEAD to learn Content-Type and Content-Length. On any
// failure it returns a zero Shape and the caller uses defaults.
func (h *Handler) probe(r *http.Request) Shape {
	host := r.Host
	req, err := http.NewRequestWithContext(r.Context(), http.MethodHead, "https://"+host+r.URL.RequestURI(), nil)
	if err != nil {
		return Shape{}
	}
	req.Host = hostOnly(host)
	resp, err := h.client.Do(req)
	if err != nil {
		return Shape{}
	}
	defer resp.Body.Close()
	return Shape{
		ContentType: resp.Header.Get("Content-Type"),
		Length:      resp.ContentLength,
	}
}

func defaultContentType(media, path string) string {
	switch media {
	case MediaJS:
		return "application/javascript"
	case MediaImage:
		if strings.HasSuffix(strings.ToLower(path), ".png") {
			return "image/png"
		}
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

func defaultLength(media string) int64 {
	switch media {
	case MediaJS:
		return 256
	case MediaImage:
		return int64(len(gif1x1))
	default:
		return 1024
	}
}

func parseRange(h string, size int64) (start, end int64, ok bool) {
	if !strings.HasPrefix(h, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(h, "bytes=")
	if strings.ContainsRune(spec, ',') {
		return 0, 0, false // multi-range not supported
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false
	}
	startS, endS := spec[:dash], spec[dash+1:]
	switch {
	case startS == "" && endS != "": // suffix range: last N bytes
		n, err := strconv.ParseInt(endS, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true
	case startS != "":
		s, err := strconv.ParseInt(startS, 10, 64)
		if err != nil || s < 0 || s >= size {
			return 0, 0, false
		}
		e := size - 1
		if endS != "" {
			e, err = strconv.ParseInt(endS, 10, 64)
			if err != nil || e < s {
				return 0, 0, false
			}
			if e >= size {
				e = size - 1
			}
		}
		return s, e, true
	default:
		return 0, 0, false
	}
}

func dialViaResolver(res Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := res.LookupIP(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}
