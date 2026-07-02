// Package passthrough handles domains that must not be MITM'd (certificate
// pinning, must-not-modify): it peeks the TLS SNI without terminating, resolves
// the real IP via the independent resolver, and splices the raw TCP stream to
// the origin. The client's own TLS session terminates at the real server, so
// pinning is preserved and mirage-chaff never sees the plaintext.
package passthrough

import (
	"context"
	"io"
	"net"
	"time"
)

// Resolver resolves a hostname to IPs via the independent resolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// Splice connects client to sni:port (real IP resolved via res) and copies bytes
// in both directions until either side closes. first is the already-read prefix
// (e.g. the buffered ClientHello) that must be replayed to the origin.
func Splice(ctx context.Context, client net.Conn, first []byte, sni, port string, res Resolver) error {
	ips, err := res.LookupIP(ctx, sni)
	if err != nil {
		return err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var upstream net.Conn
	for _, ip := range ips {
		upstream, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			break
		}
	}
	if upstream == nil {
		return err
	}
	defer upstream.Close()

	if len(first) > 0 {
		if _, err := upstream.Write(first); err != nil {
			return err
		}
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); halfClose(upstream); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); halfClose(client); done <- struct{}{} }()
	<-done
	<-done
	return nil
}

// halfClose closes the write side of a TCP connection if supported, so an EOF in
// one direction is propagated without tearing down the other direction early.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
