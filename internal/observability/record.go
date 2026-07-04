package observability

import (
	"encoding/json"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is one intercepted request/response summary. It feeds the structured
// log, the metrics counters, and the live-traffic ring buffer (Phase 6).
type Record struct {
	Time        time.Time `json:"time"`
	Domain      string    `json:"domain"`
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	Action      string    `json:"action"`
	Rule        string    `json:"rule,omitempty"`
	Status      int       `json:"status"`
	Bytes       int64     `json:"bytes"`
	ContentType string    `json:"content_type,omitempty"`
	MediaType   string    `json:"media_type,omitempty"`
	Rewritten   bool      `json:"rewritten,omitempty"`
}

// Recorder aggregates request records: it emits a redacted structured log line,
// bumps counters, and keeps a bounded ring buffer of recent records.
type Recorder struct {
	redact bool

	mu         sync.Mutex
	ring       []Record
	next       int
	full       bool
	byAction   map[string]int64
	byStatus   map[int]int64
	total      int64
	bytesTotal int64
}

// NewRecorder builds a Recorder with a ring buffer of ringSize records.
func NewRecorder(redact bool, ringSize int) *Recorder {
	if ringSize <= 0 {
		ringSize = 1024
	}
	return &Recorder{
		redact:   redact,
		ring:     make([]Record, ringSize),
		byAction: make(map[string]int64),
		byStatus: make(map[int]int64),
	}
}

// SetRedact toggles redaction (reload-safe log.redact).
func (r *Recorder) SetRedact(v bool) {
	r.mu.Lock()
	r.redact = v
	r.mu.Unlock()
}

// Log records rec: append to the ring, bump counters, and emit a JSON log line
// (redacted when enabled — masks query values so Loki never receives raw
// identifiers, design doc §Loki redact).
func (r *Recorder) Log(rec Record) {
	r.mu.Lock()
	redact := r.redact
	r.ring[r.next] = rec
	r.next = (r.next + 1) % len(r.ring)
	if r.next == 0 {
		r.full = true
	}
	r.byAction[rec.Action]++
	r.byStatus[rec.Status]++
	r.total++
	r.bytesTotal += rec.Bytes
	r.mu.Unlock()

	logged := rec
	if redact {
		logged.Path = RedactURL(rec.Path)
	}
	if b, err := json.Marshal(logged); err == nil {
		log.Printf("req %s", b)
	}
}

// SnapshotSince returns records logged after position sinceSeq (the monotonic
// total count previously returned) plus the current sequence position. It powers
// the live SSE stream: callers pass back the returned seq each tick so delivery
// continues correctly even after the ring buffer has wrapped (the length of the
// ring is constant once full, so it cannot be used as a cursor). Records older
// than the ring can hold are necessarily dropped; only what remains is returned.
func (r *Recorder) SnapshotSince(sinceSeq int64) (recs []Record, seq int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seq = r.total
	newCount := seq - sinceSeq
	if newCount <= 0 {
		return nil, seq
	}
	// Records currently retained in the ring, oldest first.
	var buffered []Record
	if r.full {
		buffered = append(buffered, r.ring[r.next:]...)
		buffered = append(buffered, r.ring[:r.next]...)
	} else {
		buffered = append(buffered, r.ring[:r.next]...)
	}
	if int64(len(buffered)) > newCount {
		buffered = buffered[int64(len(buffered))-newCount:]
	}
	if r.redact {
		for i := range buffered {
			buffered[i].Path = RedactURL(buffered[i].Path)
		}
	}
	return buffered, seq
}

// Seq returns the current monotonic record count (an SSE cursor start point).
func (r *Recorder) Seq() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Snapshot returns up to n most-recent records (newest last). n<=0 returns all.
func (r *Recorder) Snapshot(n int) []Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Record
	if r.full {
		out = append(out, r.ring[r.next:]...)
		out = append(out, r.ring[:r.next]...)
	} else {
		out = append(out, r.ring[:r.next]...)
	}
	if r.redact {
		for i := range out {
			out[i].Path = RedactURL(out[i].Path)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// WriteMetrics writes Prometheus-format counters for the observability /metrics
// endpoint.
func (r *Recorder) WriteMetrics(sb *strings.Builder) {
	r.mu.Lock()
	defer r.mu.Unlock()

	sb.WriteString("# HELP mirage_chaff_requests_total Requests handled, by action.\n")
	sb.WriteString("# TYPE mirage_chaff_requests_total counter\n")
	actions := make([]string, 0, len(r.byAction))
	for a := range r.byAction {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	for _, a := range actions {
		sb.WriteString("mirage_chaff_requests_total{action=\"" + a + "\"} ")
		sb.WriteString(itoa(r.byAction[a]) + "\n")
	}

	sb.WriteString("# HELP mirage_chaff_responses_total Responses by HTTP status class.\n")
	sb.WriteString("# TYPE mirage_chaff_responses_total counter\n")
	classes := map[string]int64{}
	for code, n := range r.byStatus {
		classes[statusClass(code)] += n
	}
	for _, c := range []string{"2xx", "3xx", "4xx", "5xx", "other"} {
		if classes[c] > 0 {
			sb.WriteString("mirage_chaff_responses_total{class=\"" + c + "\"} " + itoa(classes[c]) + "\n")
		}
	}

	sb.WriteString("# HELP mirage_chaff_response_bytes_total Total response bytes served.\n")
	sb.WriteString("# TYPE mirage_chaff_response_bytes_total counter\n")
	sb.WriteString("mirage_chaff_response_bytes_total " + itoa(r.bytesTotal) + "\n")
}

func statusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}

// RedactURL keeps the path but replaces every query value with REDACTED.
func RedactURL(raw string) string {
	i := strings.IndexByte(raw, '?')
	if i < 0 {
		return raw
	}
	path, query := raw[:i], raw[i+1:]
	q, err := url.ParseQuery(query)
	if err != nil {
		return path + "?REDACTED"
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(path)
	b.WriteByte('?')
	for idx, k := range keys {
		if idx > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteString("=REDACTED")
	}
	return b.String()
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
