package quic

// readVarint decodes a QUIC variable-length integer (RFC 9000 §16). It returns
// the value and the number of bytes consumed, or n=0 on insufficient input.
func readVarint(b []byte) (value uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	prefix := b[0] >> 6
	length := 1 << prefix // 1, 2, 4, or 8
	if len(b) < length {
		return 0, 0
	}
	value = uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		value = value<<8 | uint64(b[i])
	}
	return value, length
}
