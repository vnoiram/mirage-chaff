package quic

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

// TestParseInitialSNI captures a real QUIC v1 Initial datagram emitted by the
// quic-go client and verifies our from-scratch RFC 9001 parser recovers the SNI.
func TestParseInitialSNI(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	const wantSNI = "pinned.example.test"
	got := make(chan []byte, 8)
	go func() {
		for {
			buf := make([]byte, 2048)
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- buf[:n]
		}
	}()

	// Dial the (silent) socket; the client sends its Initial(s) then times out.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_, _ = quicgo.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{
			ServerName:         wantSNI,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		}, &quicgo.Config{})
	}()

	// The ClientHello may span multiple Initial datagrams; feed the extractor
	// until it recovers the SNI (mirrors what the passthrough relay does).
	var ext SNIExtractor
	for {
		select {
		case datagram := <-got:
			if sni, done := ext.Feed(datagram); done {
				if sni != wantSNI {
					t.Fatalf("sni = %q, want %q", sni, wantSNI)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("did not recover SNI from Initial datagrams")
		}
	}
}

func TestReadVarint(t *testing.T) {
	cases := []struct {
		in  []byte
		val uint64
		n   int
	}{
		{[]byte{0x25}, 37, 1},
		{[]byte{0x7b, 0xbd}, 15293, 2},
		{[]byte{0x00}, 0, 1},
	}
	for _, c := range cases {
		v, n := readVarint(c.in)
		if v != c.val || n != c.n {
			t.Errorf("readVarint(%x) = (%d,%d), want (%d,%d)", c.in, v, n, c.val, c.n)
		}
	}
	if _, n := readVarint(nil); n != 0 {
		t.Error("empty input should return n=0")
	}
}
