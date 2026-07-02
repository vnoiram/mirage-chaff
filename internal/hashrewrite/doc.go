// Package hashrewrite parses manifests (m3u8/mpd), VAST/VMAP XML, HTML SRI and
// JSON integrity to correlate URL<->hash, and rewrites reference hashes to decoy
// hashes. Correlation prefers same-connection / cookie / manifest->segment
// relationships over a client-IP+time window (design doc C-3); on uncertainty it
// falls back to forward-asis.
package hashrewrite
