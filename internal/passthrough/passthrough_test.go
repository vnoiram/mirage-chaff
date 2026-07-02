package passthrough

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

type staticResolver struct{ ip net.IP }

func (s staticResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{s.ip}, nil
}

func TestPeekClientHelloExtractsSNI(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	const want = "pinned.test.example"
	go func() {
		// tls.Client writes a ClientHello carrying the SNI; the handshake then
		// blocks waiting for a ServerHello, which we never send.
		_ = tls.Client(c1, &tls.Config{ServerName: want, InsecureSkipVerify: true}).HandshakeContext(context.Background())
	}()

	sni, replay, err := PeekClientHello(c2)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if sni != want {
		t.Fatalf("sni = %q, want %q", sni, want)
	}
	if replay == nil {
		t.Fatal("replay conn is nil")
	}
}

func TestSpliceReplaysAndEchoes(t *testing.T) {
	// Origin echoes everything back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn)
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	clientSrv, clientTest := net.Pipe()
	defer clientTest.Close()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = Splice(ctx, clientSrv, []byte("ping"), "origin.test.example", port, staticResolver{net.IPv4(127, 0, 0, 1)})
	}()

	// The replayed prefix "ping" should be echoed back to the client side.
	_ = clientTest.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(clientTest, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}
