package passthrough

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// PeekClientHello reads the first TLS record from conn, extracts the SNI, and
// returns a net.Conn that replays every byte read (so the caller can either
// terminate TLS or splice to an origin). SNI is "" if absent or unparseable; the
// returned conn is still usable.
func PeekClientHello(conn net.Conn) (sni string, replay net.Conn, err error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return "", &prefixConn{Conn: conn}, err
	}
	// TLS record: type(1)=22 handshake, version(2), length(2).
	if hdr[0] != 0x16 {
		return "", &prefixConn{Conn: conn, buf: hdr}, fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen <= 0 || recLen > 1<<16 {
		return "", &prefixConn{Conn: conn, buf: hdr}, fmt.Errorf("bad record length")
	}
	body := make([]byte, recLen)
	if _, err := readFull(conn, body); err != nil {
		return "", &prefixConn{Conn: conn, buf: hdr}, err
	}
	raw := append(hdr, body...)
	sni = parseSNI(body)
	return sni, &prefixConn{Conn: conn, buf: raw}, nil
}

// ParseSNI extracts the SNI host_name from a TLS ClientHello handshake message
// (handshake type byte + length + body). Exported for reuse by the QUIC Initial
// parser, which recovers the same ClientHello from CRYPTO frames.
func ParseSNI(handshake []byte) string { return parseSNI(handshake) }

// parseSNI extracts the SNI host_name from a ClientHello handshake body.
func parseSNI(b []byte) string {
	// Handshake: type(1)=1 ClientHello, length(3), then body.
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	b = b[4:]
	// version(2) + random(32)
	if len(b) < 34 {
		return ""
	}
	b = b[34:]
	// session_id
	if len(b) < 1 {
		return ""
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return ""
	}
	b = b[sidLen:]
	// cipher_suites
	if len(b) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < csLen {
		return ""
	}
	b = b[csLen:]
	// compression_methods
	if len(b) < 1 {
		return ""
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return ""
	}
	b = b[cmLen:]
	// extensions
	if len(b) < 2 {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < extTotal {
		return ""
	}
	b = b[:extTotal]
	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[0:2])
		extLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if len(b) < extLen {
			return ""
		}
		ext := b[:extLen]
		b = b[extLen:]
		if extType != 0x0000 { // server_name
			continue
		}
		// ServerNameList: list_len(2), then entries: type(1), name_len(2), name.
		if len(ext) < 2 {
			return ""
		}
		listLen := int(binary.BigEndian.Uint16(ext[0:2]))
		ext = ext[2:]
		if len(ext) < listLen {
			return ""
		}
		ext = ext[:listLen]
		for len(ext) >= 3 {
			nameType := ext[0]
			nameLen := int(binary.BigEndian.Uint16(ext[1:3]))
			ext = ext[3:]
			if len(ext) < nameLen {
				return ""
			}
			name := ext[:nameLen]
			ext = ext[nameLen:]
			if nameType == 0 { // host_name
				return string(name)
			}
		}
	}
	return ""
}

func readFull(conn net.Conn, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := conn.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// prefixConn replays buffered bytes before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	buf []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// Buffered returns the bytes already read from the connection (the ClientHello),
// so callers that splice can replay them to the origin.
func (c *prefixConn) Buffered() []byte { return c.buf }
