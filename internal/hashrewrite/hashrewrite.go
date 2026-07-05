// Package hashrewrite keeps integrity checks passing when a referenced resource
// is swapped for a mimic decoy: it finds URL<->hash references (Subresource
// Integrity in HTML, and integrity fields in JSON) and rewrites the reference
// hash to the decoy's hash.
//
// Rewriting is only possible when BOTH the reference (e.g. the HTML) and the
// target (the decoyed resource) pass through mirage-chaff. When the decoy hash
// for a URL is unknown, that reference is left untouched and the caller should
// fall back to forward-asis for the target (design doc C-3 fallback).
package hashrewrite

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

// Hasher returns the decoy integrity for an absolute-or-relative resource URL as
// found in the document. ok is false when the URL was not decoyed (leave as-is).
type Hasher func(url string) (integrity string, ok bool)

// Integrity formats a decoy hash as an SRI token ("sha256-<base64>").
func Integrity(sum [32]byte) string {
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

// IntegrityOf computes the SRI token for raw bytes.
func IntegrityOf(b []byte) string {
	sum := sha256.Sum256(b)
	return Integrity(sum)
}

var (
	// script/link tags (SRI applies to these).
	sriTagRe = regexp.MustCompile(`(?is)<(script|link)\b[^>]*>`)
	srcRe    = regexp.MustCompile(`(?is)\b(?:src|href)\s*=\s*("([^"]*)"|'([^']*)')`)
	integRe  = regexp.MustCompile(`(?is)\bintegrity\s*=\s*("([^"]*)"|'([^']*)')`)
)

// RewriteSRI rewrites the integrity attribute of any <script>/<link> whose
// URL the Hasher recognizes as decoyed. It preserves all other bytes and
// reports how many attributes were rewritten.
func RewriteSRI(html []byte, h Hasher) (out []byte, rewritten int) {
	result := sriTagRe.ReplaceAllFunc(html, func(tag []byte) []byte {
		src := attrValue(srcRe.FindSubmatch(tag))
		if src == "" {
			return tag
		}
		integMatch := integRe.FindSubmatchIndex(tag)
		if integMatch == nil {
			return tag
		}
		newIntegrity, ok := h(src)
		if !ok {
			return tag
		}
		// Replace the whole integrity="..." attribute value with the decoy token.
		var b strings.Builder
		b.Write(tag[:integMatch[0]])
		b.WriteString(`integrity="` + newIntegrity + `"`)
		b.Write(tag[integMatch[1]:])
		rewritten++
		return []byte(b.String())
	})
	return result, rewritten
}

// attrValue extracts the quoted value from a src/href submatch.
func attrValue(m [][]byte) string {
	if m == nil {
		return ""
	}
	if len(m) > 2 && len(m[2]) > 0 {
		return string(m[2])
	}
	if len(m) > 3 && len(m[3]) > 0 {
		return string(m[3])
	}
	return ""
}

// jsonIntegrityRe matches "integrity":"sha256-..." style fields alongside a
// preceding "url"/"src" key within a small window (best-effort JSON manifests).
var jsonIntegrityRe = regexp.MustCompile(`(?is)"(url|src|uri)"\s*:\s*"([^"]+)"([^{}]*?)"integrity"\s*:\s*"([^"]*)"`)

// RewriteJSONIntegrity rewrites "integrity" fields that follow a "url"/"src"/
// "uri" field when the URL is decoyed. Best-effort for JSON manifests.
func RewriteJSONIntegrity(body []byte, h Hasher) (out []byte, rewritten int) {
	result := jsonIntegrityRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := jsonIntegrityRe.FindSubmatch(m)
		if sub == nil {
			return m
		}
		key, url := string(sub[1]), string(sub[2])
		newIntegrity, ok := h(url)
		if !ok {
			return m
		}
		rewritten++
		// Rebuild with the new integrity value, preserving the original key name
		// (url/src/uri) and the bytes between it and the integrity field.
		return []byte(`"` + key + `":"` + url + `"` + string(sub[3]) + `"integrity":"` + newIntegrity + `"`)
	})
	return result, rewritten
}
