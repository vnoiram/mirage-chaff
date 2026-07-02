// Package quic listens on UDP443 (protocols.quic). With protocols.http3 it
// terminates HTTP/3 and applies policy; otherwise it passes QUIC through by SNI.
// Default off on constrained VMs (design doc C-2).
package quic
