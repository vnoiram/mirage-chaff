// Package resolver provides the INDEPENDENT DNS resolver used for forward and
// passthrough upstream IP resolution. It must never point at AdGuard Home, or a
// rewrite loop results (design doc: independent resolver). Supported forms:
//
//	host / host:53 / udp://host        plain DNS over UDP+TCP
//	tls://host[:853]                   DNS-over-TLS
//	https://host/dns-query             DNS-over-HTTPS (RFC 8484)
package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Resolver resolves hostnames to IPs using an ordered list of upstreams, trying
// each until one answers.
type Resolver struct {
	lookups []lookupFunc
	timeout time.Duration
}

type lookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// New builds a Resolver from the configured upstream strings.
func New(upstreams []string) (*Resolver, error) {
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("no upstream resolvers configured")
	}
	r := &Resolver{timeout: 5 * time.Second}
	for _, up := range upstreams {
		lf, err := buildLookup(up)
		if err != nil {
			return nil, fmt.Errorf("resolver %q: %w", up, err)
		}
		r.lookups = append(r.lookups, lf)
	}
	return r, nil
}

// LookupIP resolves host, trying each upstream in order. If host is already an IP
// literal it is returned directly.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var lastErr error
	for _, lf := range r.lookups {
		ips, err := lf(ctx, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address found for %q", host)
	}
	return nil, lastErr
}

func buildLookup(up string) (lookupFunc, error) {
	switch {
	case strings.HasPrefix(up, "https://"):
		return dohLookup(up), nil
	case strings.HasPrefix(up, "tls://"):
		addr := strings.TrimPrefix(up, "tls://")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "853")
		}
		return netResolverLookup(dotDialer(addr)), nil
	default:
		addr := strings.TrimPrefix(up, "udp://")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		return netResolverLookup(plainDialer(addr)), nil
	}
}

// netResolverLookup wraps a custom-dialing *net.Resolver (PreferGo so it uses the
// dialer for plain DNS / DoT rather than the system resolver).
func netResolverLookup(dial func(ctx context.Context, network, address string) (net.Conn, error)) lookupFunc {
	res := &net.Resolver{PreferGo: true, Dial: dial}
	return func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := res.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}
}

func plainDialer(server string) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, server)
	}
}

func dotDialer(server string) func(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(server)
	d := &tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", server)
	}
}

// dohLookup returns a lookup that queries A and AAAA over DoH (RFC 8484 POST).
func dohLookup(endpoint string) lookupFunc {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context, host string) ([]net.IP, error) {
		var ips []net.IP
		for _, qt := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			got, err := dohQuery(ctx, client, endpoint, host, qt)
			if err == nil {
				ips = append(ips, got...)
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DoH: no address for %q", host)
		}
		return ips, nil
	}
}

func dohQuery(ctx context.Context, client *http.Client, endpoint, host string, qt dnsmessage.Type) ([]net.IP, error) {
	name, err := dnsmessage.NewName(dnsName(host))
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qt, Class: dnsmessage.ClassINET}},
	}
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseAnswers(body, name, qt)
}

func parseAnswers(wire []byte, wantName dnsmessage.Name, wantType dnsmessage.Type) ([]net.IP, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil {
		return nil, err
	}
	if !hdr.Response {
		return nil, fmt.Errorf("DoH: reply is not a response")
	}
	if hdr.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DoH: server returned %s", hdr.RCode)
	}
	// Validate the echoed question matches our query, so answers for a different
	// name/type are never accepted (basic anti-spoofing on the DoH channel).
	matched := false
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if q.Type == wantType && strings.EqualFold(q.Name.String(), wantName.String()) {
			matched = true
		}
	}
	if !matched {
		return nil, fmt.Errorf("DoH: response question does not match query")
	}
	var ips []net.IP
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, net.IP(r.A[:]))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, net.IP(r.AAAA[:]))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	return ips, nil
}

func dnsName(host string) string {
	if !strings.HasSuffix(host, ".") {
		return host + "."
	}
	return host
}
