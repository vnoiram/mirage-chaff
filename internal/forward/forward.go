package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// htmlModifyLimit caps the body size we buffer to rewrite (hashrewrite). Larger
// bodies stream through unmodified.
const htmlModifyLimit = 4 << 20

// Resolver resolves a hostname to IPs via the independent resolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// defaultScrubbedUA is the User-Agent substituted on scrubbed requests when
// Options.ScrubbedUA is empty.
const defaultScrubbedUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"

// trackingIDParams are common client-identifier query/body parameters removed on
// scrubbed requests.
var trackingIDParams = map[string]bool{
	"uid": true, "user_id": true, "userid": true, "cid": true, "client_id": true,
	"clientid": true, "gid": true, "did": true, "device_id": true, "deviceid": true,
	"fbp": true, "fbc": true, "ga": true, "_ga": true, "gclid": true, "idfa": true,
	"aaid": true, "advertising_id": true, "sessionid": true, "session_id": true,
}

// trackingHeaders are request headers removed on scrubbed requests.
var trackingHeaders = []string{
	"Cookie", "Referer", "Referrer", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Forwarded-Proto", "X-Real-Ip", "X-Client-Ip", "X-Device-Id", "X-User-Id",
	"X-Request-Id", "Dnt", "Sec-Ch-Ua-Platform-Version", "Sec-Ch-Ua-Model",
}

// customTrackingHeaderRe matches vendor tracking headers by shape.
var customTrackingHeaderRe = regexp.MustCompile(`(?i)^(x-)?(amzn|ad|track|analytics|telemetry|beacon|fingerprint)`)

// Forwarder forwards intercepted requests to the real origin, resolving the real
// IP via the independent resolver. It offers two actions:
//   - Asis:     unmodified passthrough of the decrypted request/response.
//   - Scrubbed: strip/randomize identifying data before forwarding (privacy).
type Forwarder struct {
	res      Resolver
	asis     *httputil.ReverseProxy
	scrubbed *httputil.ReverseProxy
}

// Options tunes the Forwarder.
type Options struct {
	// TLSClientConfig overrides the client TLS config used to reach origins
	// (tests inject a RootCAs pool). nil uses system defaults (verify real certs).
	TLSClientConfig *tls.Config
	// OnError is called when forwarding fails, so the caller can fail safe (e.g.
	// serve a stub). If nil, a 502 is written.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
	// BodyModifier, if set, may rewrite a buffered response body (used for
	// hashrewrite/SRI on HTML/JSON manifests). It receives the Content-Type and
	// body and returns the possibly-changed body plus whether it changed. Only
	// called for uncompressed bodies with a known length under htmlModifyLimit.
	BodyModifier func(contentType string, body []byte) ([]byte, bool)
	// ScrubbedUA overrides the User-Agent set on scrubbed requests. Empty uses
	// defaultScrubbedUA.
	ScrubbedUA string
}

// New builds a Forwarder using res for upstream resolution.
func New(res Resolver, opts Options) *Forwarder {
	transport := &http.Transport{
		DialContext:           dialViaResolver(res),
		TLSClientConfig:       opts.TLSClientConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	ua := opts.ScrubbedUA
	if ua == "" {
		ua = defaultScrubbedUA
	}
	f := &Forwarder{res: res}
	errHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		if opts.OnError != nil {
			opts.OnError(w, r, err)
			return
		}
		log.Printf("forward error for %s: %v", r.Host, err)
		w.WriteHeader(http.StatusBadGateway)
	}
	f.asis = &httputil.ReverseProxy{
		Rewrite:        rewriteTo(false, ""),
		Transport:      transport,
		ModifyResponse: modifyResponse(false, opts.BodyModifier),
		ErrorHandler:   errHandler,
	}
	f.scrubbed = &httputil.ReverseProxy{
		Rewrite:        rewriteTo(true, ua),
		Transport:      transport,
		ModifyResponse: modifyResponse(true, opts.BodyModifier),
		ErrorHandler:   errHandler,
	}
	return f
}

// Asis forwards r to its origin unmodified.
func (f *Forwarder) Asis(w http.ResponseWriter, r *http.Request) { f.asis.ServeHTTP(w, r) }

// Scrubbed forwards r to its origin after removing identifying data.
func (f *Forwarder) Scrubbed(w http.ResponseWriter, r *http.Request) { f.scrubbed.ServeHTTP(w, r) }

// rewriteTo builds a ReverseProxy Rewrite that targets the request's own host
// over HTTPS. When scrub is set, identifying data is stripped from the outbound
// request.
func rewriteTo(scrub bool, ua string) func(*httputil.ProxyRequest) {
	return func(pr *httputil.ProxyRequest) {
		// Preserve the authority (host[:port]); the transport's resolver-backed
		// dialer splits it and resolves the host. Production authorities carry no
		// port (443 implied); an explicit port is honored (e.g. tests).
		authority := pr.In.Host
		pr.Out.URL.Scheme = "https"
		pr.Out.URL.Host = authority
		pr.Out.Host = hostOnly(authority)
		// Do not leak the client IP via X-Forwarded-For.
		pr.Out.Header.Del("X-Forwarded-For")
		if scrub {
			scrubRequest(pr.Out, ua)
		}
	}
}

func scrubRequest(r *http.Request, ua string) {
	for _, h := range trackingHeaders {
		r.Header.Del(h)
	}
	for name := range r.Header {
		if customTrackingHeaderRe.MatchString(name) {
			r.Header.Del(name)
		}
	}
	r.Header.Set("User-Agent", ua)

	// Strip client-identifier query parameters.
	if q := r.URL.Query(); len(q) > 0 {
		changed := false
		for k := range q {
			if trackingIDParams[strings.ToLower(k)] {
				q.Del(k)
				changed = true
			}
		}
		if changed {
			r.URL.RawQuery = q.Encode()
		}
	}
}

// modifyResponse builds a ReverseProxy ModifyResponse that (optionally) scrubs
// tracking response headers and (optionally) rewrites a buffered HTML/JSON body
// via mod (hashrewrite/SRI).
func modifyResponse(scrub bool, mod func(string, []byte) ([]byte, bool)) func(*http.Response) error {
	return func(resp *http.Response) error {
		if scrub {
			resp.Header.Del("Set-Cookie")
			resp.Header.Del("P3p")
			resp.Header.Del("Report-To")
			resp.Header.Del("Nel")
		}
		if mod == nil {
			return nil
		}
		return rewriteBody(resp, mod)
	}
}

// rewriteBody buffers a small, uncompressed HTML/JSON body, applies mod, and
// replaces the response body + Content-Length when it changed. Compressed,
// unknown-length, or oversized bodies stream through untouched.
func rewriteBody(resp *http.Response, mod func(string, []byte) ([]byte, bool)) error {
	ct := resp.Header.Get("Content-Type")
	if !isRewritable(ct) {
		return nil
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return nil // don't touch compressed bodies
	}
	if resp.ContentLength < 0 || resp.ContentLength > htmlModifyLimit {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, htmlModifyLimit))
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	newBody, changed := mod(ct, body)
	if !changed {
		newBody = body
	}
	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	return nil
}

func isRewritable(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/html") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "dash+xml") ||
		strings.Contains(ct, "mpegurl")
}

// dialViaResolver dials addr's host through the independent resolver, so upstream
// IPs never come from AdGuard Home. SNI stays the original host (Go derives it
// from the address host part), so origin cert verification still works.
func dialViaResolver(res Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
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
