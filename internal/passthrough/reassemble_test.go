package passthrough

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// buildClientHello builds a minimal TLS ClientHello handshake message
// (type + 3-byte length + body) carrying sni in a server_name extension.
func buildClientHello(sni string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id length 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher_suites: len 2 + one suite
	body = append(body, 0x01, 0x00)             // compression_methods: len 1 + null

	name := []byte(sni)
	entry := []byte{0x00, byte(len(name) >> 8), byte(len(name))} // host_name + name_len
	entry = append(entry, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext := append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...) // server_name ext
	exts := append([]byte{byte(len(ext) >> 8), byte(len(ext))}, ext...)
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// record wraps a handshake fragment in a TLS handshake record header.
func record(fragment []byte) []byte {
	return append([]byte{0x16, 0x03, 0x03, byte(len(fragment) >> 8), byte(len(fragment))}, fragment...)
}

// sliceConn is a net.Conn that reads from a fixed byte slice and discards writes.
type sliceConn struct{ r *bytes.Reader }

func (c *sliceConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *sliceConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *sliceConn) Close() error                     { return nil }
func (c *sliceConn) LocalAddr() net.Addr              { return nil }
func (c *sliceConn) RemoteAddr() net.Addr             { return nil }
func (c *sliceConn) SetDeadline(time.Time) error      { return nil }
func (c *sliceConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sliceConn) SetWriteDeadline(time.Time) error { return nil }

// TestPeekClientHelloReassemblesRecords verifies a ClientHello split across two
// TLS records is reassembled so the SNI is still recovered (C-1: without this,
// pinned passthrough domains with large/fragmented ClientHellos are mis-routed).
func TestPeekClientHelloReassemblesRecords(t *testing.T) {
	const want = "pinned.example.test"
	hs := buildClientHello(want)

	// Split the handshake mid-message across two handshake records.
	split := 12
	stream := append(record(hs[:split]), record(hs[split:])...)

	conn := &sliceConn{r: bytes.NewReader(stream)}
	sni, replay, err := PeekClientHello(conn)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if sni != want {
		t.Fatalf("sni = %q, want %q", sni, want)
	}
	// The replay buffer must contain every raw byte read (both records) so a
	// downstream splice/terminate sees the full ClientHello.
	if got := replay.(*prefixConn).Buffered(); !bytes.Equal(got, stream) {
		t.Fatalf("replay buffered %d bytes, want %d", len(got), len(stream))
	}
}

// TestPeekClientHelloSingleRecord confirms the common single-record path still
// works after the multi-record change.
func TestPeekClientHelloSingleRecord(t *testing.T) {
	const want = "single.example.test"
	stream := record(buildClientHello(want))
	conn := &sliceConn{r: bytes.NewReader(stream)}
	sni, _, err := PeekClientHello(conn)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if sni != want {
		t.Fatalf("sni = %q, want %q", sni, want)
	}
}
