package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/vnoiram/mirage-chaff/internal/passthrough"
	"golang.org/x/crypto/hkdf"
)

// quicV1InitialSalt is the RFC 9001 §5.2 initial salt for QUIC v1.
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// ParseInitialSNI extracts the TLS SNI from a single QUIC v1 Initial datagram.
// It works when the ClientHello fits (contiguously from offset 0) in this one
// datagram. Large ClientHellos are fragmented across datagrams — use SNIExtractor
// to reassemble across several (design doc C-2: QUIC coalescing/fragmentation).
func ParseInitialSNI(data []byte) (string, error) {
	chunks, err := extractInitialCrypto(data)
	if err != nil {
		return "", err
	}
	sni := passthrough.ParseSNI(joinCryptoChunks(chunks))
	if sni == "" {
		return "", fmt.Errorf("no SNI in ClientHello (may be fragmented across datagrams)")
	}
	return sni, nil
}

// SNIExtractor reassembles CRYPTO frames across multiple client Initial datagrams
// until the ClientHello is complete enough to yield the SNI. The relay feeds it
// the first few client datagrams before routing.
type SNIExtractor struct {
	chunks  []cryptoChunk
	packets int
}

// Feed adds one datagram. It returns the SNI once recoverable, and done=true when
// the SNI is found or the extractor gives up (after too many datagrams).
func (e *SNIExtractor) Feed(data []byte) (sni string, done bool) {
	e.packets++
	if chunks, err := extractInitialCrypto(data); err == nil {
		e.chunks = append(e.chunks, chunks...)
		if s := passthrough.ParseSNI(joinCryptoChunks(e.chunks)); s != "" {
			return s, true
		}
	}
	return "", e.packets >= 8
}

// extractInitialCrypto decrypts a QUIC v1 Initial datagram and returns its CRYPTO
// frame chunks (with offsets), by deriving initial secrets from the DCID,
// removing header protection, and AEAD-decrypting the packet (RFC 9000 / 9001).
func extractInitialCrypto(data []byte) ([]cryptoChunk, error) {
	if len(data) < 7 || data[0]&0x80 == 0 {
		return nil, fmt.Errorf("not a long header")
	}
	if data[0]&0x30 != 0x00 {
		return nil, fmt.Errorf("not an Initial packet")
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if version != 0x00000001 {
		return nil, fmt.Errorf("unsupported QUIC version %#x", version)
	}

	pos := 5
	dcidLen := int(data[pos])
	pos++
	if pos+dcidLen > len(data) {
		return nil, fmt.Errorf("truncated DCID")
	}
	dcid := data[pos : pos+dcidLen]
	pos += dcidLen
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated SCID len")
	}
	scidLen := int(data[pos])
	pos++
	pos += scidLen
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated after SCID")
	}
	tokenLen, n := readVarint(data[pos:])
	if n == 0 {
		return nil, fmt.Errorf("bad token length")
	}
	pos += n + int(tokenLen)
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated after token")
	}
	payloadLen, n := readVarint(data[pos:])
	if n == 0 {
		return nil, fmt.Errorf("bad payload length")
	}
	pos += n
	pnOffset := pos
	if pnOffset+4+16 > len(data) {
		return nil, fmt.Errorf("packet too short for sampling")
	}

	key, iv, hp, err := deriveClientInitialKeys(dcid)
	if err != nil {
		return nil, err
	}

	// Remove header protection using a sample taken 4 bytes past the PN offset.
	sample := data[pnOffset+4 : pnOffset+4+16]
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	hdr := make([]byte, pnOffset)
	copy(hdr, data[:pnOffset])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1

	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = data[pnOffset+i] ^ mask[1+i]
	}
	hdr = append(hdr, pnBytes...)

	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	// Ciphertext (incl 16-byte tag) spans the rest of the declared payload.
	ctStart := pnOffset + pnLen
	ctEnd := pnOffset + int(payloadLen)
	if ctEnd > len(data) || ctStart > ctEnd {
		return nil, fmt.Errorf("ciphertext bounds out of range")
	}
	ciphertext := data[ctStart:ctEnd]

	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	pnFull := make([]byte, 8)
	binary.BigEndian.PutUint64(pnFull, pn)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pnFull[i]
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return nil, fmt.Errorf("decrypt Initial: %w", err)
	}
	return cryptoFrames(plaintext), nil
}

func deriveClientInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = hkdfExpandLabel(clientSecret, "quic key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = hkdfExpandLabel(clientSecret, "quic iv", 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = hkdfExpandLabel(clientSecret, "quic hp", 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with the
// "tls13 " prefix, as used by QUIC.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	var info []byte
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, info)
	if _, err := r.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type cryptoChunk struct {
	off  uint64
	data []byte
}

// cryptoFrames extracts CRYPTO frame chunks from Initial plaintext, skipping
// PADDING/PING and stopping at the first unhandled frame type.
func cryptoFrames(frames []byte) []cryptoChunk {
	var chunks []cryptoChunk
	i := 0
	for i < len(frames) {
		ft := frames[i]
		i++
		switch ft {
		case 0x00, 0x01: // PADDING, PING
			continue
		case 0x06: // CRYPTO
			off, n := readVarint(frames[i:])
			if n == 0 {
				return chunks
			}
			i += n
			ln, n := readVarint(frames[i:])
			if n == 0 {
				return chunks
			}
			i += n
			if i+int(ln) > len(frames) {
				return chunks
			}
			chunks = append(chunks, cryptoChunk{off: off, data: frames[i : i+int(ln)]})
			i += int(ln)
		default:
			// Unknown/unhandled frame type (e.g. ACK); stop with what we have.
			return chunks
		}
	}
	return chunks
}

// joinCryptoChunks concatenates CRYPTO chunks into a contiguous stream from
// offset 0, tolerating out-of-order and overlapping chunks. Stops at the first
// gap (the rest is expected in a later datagram).
func joinCryptoChunks(chunks []cryptoChunk) []byte {
	if len(chunks) == 0 {
		return nil
	}
	sorted := make([]cryptoChunk, len(chunks))
	copy(sorted, chunks)
	for a := 1; a < len(sorted); a++ {
		for b := a; b > 0 && sorted[b-1].off > sorted[b].off; b-- {
			sorted[b-1], sorted[b] = sorted[b], sorted[b-1]
		}
	}
	var out []byte
	var next uint64
	for _, c := range sorted {
		end := c.off + uint64(len(c.data))
		if c.off > next {
			break // gap
		}
		if end <= next {
			continue // fully covered by earlier chunks
		}
		out = append(out, c.data[next-c.off:]...)
		next = end
	}
	return out
}
