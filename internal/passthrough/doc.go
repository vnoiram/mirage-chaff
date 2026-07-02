// Package passthrough splices TCP (and, when enabled, QUIC/UDP) to the real IP
// resolved via the independent resolver, without terminating TLS — for
// certificate-pinned or must-not-modify domains.
package passthrough
