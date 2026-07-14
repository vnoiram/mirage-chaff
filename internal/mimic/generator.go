// Package mimic implements forward-mimic: shape-preserving decoys that satisfy
// "a real-looking resource loaded" without serving the real ad/tracker payload.
//
// Scope: image / js / binary, plus opt-in video-shaped opaque bytes. Video
// decoys are deterministic and range-consistent, but intentionally not playable
// byte-valid MP4/WebM/HLS/DASH media; callers that do not opt in fall back to
// stub/asis before generation.
//
// Generation is deterministic: the same (seed, shape) always yields identical
// bytes, so a decoy's hash can be precomputed for manifest/SRI rewriting
// (package hashrewrite) and re-derived for later Range requests.
package mimic

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Media type families.
const (
	MediaImage  = "image"
	MediaJS     = "js"
	MediaBinary = "binary"
	MediaVideo  = "video"
)

// Shape describes the decoy to produce.
type Shape struct {
	ContentType string // e.g. "application/javascript", "image/gif"
	Length      int64  // exact target byte length
	Media       string // MediaImage / MediaJS / MediaBinary / MediaVideo
}

// ErrUnsupported is returned for media that mimic will not decoy, so the caller
// falls back to stub/asis.
type ErrUnsupported struct{ Media string }

func (e *ErrUnsupported) Error() string { return "mimic: unsupported media " + e.Media }

// ClassifyContentType maps a Content-Type to a media family.
func ClassifyContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case strings.HasPrefix(ct, "video/"):
		return MediaVideo
	case strings.HasPrefix(ct, "image/"):
		return MediaImage
	case ct == "application/javascript" || ct == "text/javascript" || ct == "application/x-javascript":
		return MediaJS
	default:
		return MediaBinary
	}
}

// ClassifyExt maps a URL path extension to a media family ("" if unknown).
func ClassifyExt(path string) string {
	i := strings.LastIndexByte(path, '.')
	if i < 0 {
		return ""
	}
	switch strings.ToLower(path[i+1:]) {
	case "mp4", "webm", "m4s", "ts", "mov", "m3u8", "mpd":
		return MediaVideo
	case "gif", "png", "jpg", "jpeg", "webp", "bmp":
		return MediaImage
	case "js", "mjs":
		return MediaJS
	default:
		return ""
	}
}

// minimal valid 1x1 transparent images. Trailing bytes after the terminator are
// ignored by decoders, so we can pad to an exact length while still decoding.
var (
	gif1x1 = []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01,
		0x44, 0x00, 0x3b,
	}
	// 1x1 transparent PNG.
	png1x1 = []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
		0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
		0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44,
		0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d,
		0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42,
		0x60, 0x82,
	}
)

// Generate returns deterministic decoy bytes of exactly shape.Length for the
// given seed (the request URL). Video shapes use the opaque binary keystream;
// the handler is responsible for enforcing the allow_video opt-in gate.
func Generate(seed string, shape Shape) ([]byte, error) {
	if shape.Length < 0 {
		return nil, fmt.Errorf("mimic: negative length")
	}
	switch shape.Media {
	case MediaJS:
		return genJS(seed, shape.Length), nil
	case MediaImage:
		return genImage(seed, shape), nil
	default:
		return keystream(seed, shape.Length), nil
	}
}

// GenerateRange returns bytes [start, end] inclusive of the full decoy. It
// regenerates deterministically and slices, so ranges are always consistent.
func GenerateRange(seed string, shape Shape, start, end int64) ([]byte, error) {
	full, err := Generate(seed, shape)
	if err != nil {
		return nil, err
	}
	if start < 0 || start >= int64(len(full)) {
		return nil, fmt.Errorf("mimic: range start out of bounds")
	}
	if end >= int64(len(full)) {
		end = int64(len(full)) - 1
	}
	return full[start : end+1], nil
}

// Hash returns the SHA-256 of the decoy for seed+shape (used by hashrewrite).
func Hash(seed string, shape Shape) ([32]byte, error) {
	b, err := Generate(seed, shape)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func genJS(seed string, length int64) []byte {
	const suffix = "*/\nvar __mc=0;\n"
	const prefix = "/* "
	overhead := int64(len(prefix) + len(suffix))
	if length <= overhead {
		// Too small to pad meaningfully; emit a minimal valid no-op.
		return []byte("var __mc=0;\n")
	}
	pad := padText(seed, length-overhead)
	out := make([]byte, 0, length)
	out = append(out, prefix...)
	out = append(out, pad...)
	out = append(out, suffix...)
	return out
}

func genImage(seed string, shape Shape) []byte {
	base := gif1x1
	if strings.Contains(strings.ToLower(shape.ContentType), "png") {
		base = png1x1
	}
	if shape.Length <= int64(len(base)) {
		return base // can't shrink below a valid image; serve as-is
	}
	out := make([]byte, 0, shape.Length)
	out = append(out, base...)
	out = append(out, keystream(seed, shape.Length-int64(len(base)))...)
	return out
}

// padText returns n comment-safe bytes (base64url alphabet: no '*' or '/').
func padText(seed string, n int64) []byte {
	raw := keystream(seed, (n+3)/4*3)
	enc := base64.RawURLEncoding.EncodeToString(raw)
	if int64(len(enc)) < n {
		// shouldn't happen, but pad with 'A'
		enc += strings.Repeat("A", int(n-int64(len(enc))))
	}
	return []byte(enc[:n])
}

// keystream returns n deterministic pseudo-random bytes derived from seed via
// SHA-256 in counter mode.
func keystream(seed string, n int64) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, 0, n)
	base := sha256.Sum256([]byte(seed))
	var counter uint64
	var blockSeed [sha256.Size + 8]byte
	copy(blockSeed[:sha256.Size], base[:])
	for int64(len(out)) < n {
		binary.BigEndian.PutUint64(blockSeed[sha256.Size:], counter)
		block := sha256.Sum256(blockSeed[:])
		out = append(out, block[:]...)
		counter++
	}
	return out[:n]
}
