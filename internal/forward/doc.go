// Package forward implements forward-scrubbed (strip/randomize identifying data,
// resolve the real IP via the independent resolver, forward, reshape the
// response) and forward-asis (unmodified passthrough of decrypted traffic).
package forward
