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
	Client      string    `json:"client,omitempty"`

	CatalogID       string `json:"catalog_id,omitempty"`
	CatalogSource   string `json:"catalog_source,omitempty"`
	Category        string `json:"category,omitempty"`
	Layer           string `json:"layer,omitempty"`
	ResourceType    string `json:"resource_type,omitempty"`
	Risk            string `json:"risk,omitempty"`
	Confidence      string `json:"confidence,omitempty"`
	ReviewStatus    string `json:"review_status,omitempty"`
	Verified        bool   `json:"verified,omitempty"`
	RewriteState    string `json:"rewrite_state,omitempty"`
	CNAMETarget     string `json:"cname_target,omitempty"`
	TrackerVendor   string `json:"tracker_vendor,omitempty"`
	CNAMEConfidence string `json:"cname_confidence,omitempty"`
	ExpectedCatalog string `json:"expected_catalog,omitempty"`
	StubTemplate    string `json:"stub_template,omitempty"`
	UnknownProfile  string `json:"unknown_profile,omitempty"`
	FallbackReason  string `json:"fallback_reason,omitempty"`
	RedactionMode   string `json:"redaction_mode,omitempty"`
}

// Options controls record retention/redaction behavior.
type Options struct {
	Redact         bool
	Mode           string
	Retention      string
	DebugScopes    []DebugScope
	CatalogMetrics bool
	EmitCatalogLog bool
}

// DebugScope enables full detail for matching traffic while log.mode=debug.
type DebugScope struct {
	Domain  string
	Client  string
	Expires time.Time
}

// Recorder aggregates request records: it emits a redacted structured log line,
// bumps counters, and keeps a bounded ring buffer of recent records.
type Recorder struct {
	redact         bool
	mode           string
	debugScopes    []DebugScope
	catalogMetrics bool
	emitCatalogLog bool

	mu             sync.Mutex
	ring           []Record
	next           int
	full           bool
	byAction       map[string]int64
	byStatus       map[int]int64
	byDomain       map[string]int64
	byRule         map[string]int64
	byCatalog      map[string]int64
	byCatalogClass map[catalogMetricKey]int64
	total          int64
	bytesTotal     int64
}

type catalogMetricKey struct {
	Category     string
	Risk         string
	Verified     string
	ReviewStatus string
	SourceType   string
}

// NewRecorder builds a Recorder with a ring buffer of ringSize records.
func NewRecorder(redact bool, ringSize int) *Recorder {
	return NewRecorderWithOptions(Options{Redact: redact, Mode: "redacted"}, ringSize)
}

// NewRecorderWithOptions builds a Recorder with explicit logging options.
func NewRecorderWithOptions(opts Options, ringSize int) *Recorder {
	if ringSize <= 0 {
		ringSize = 1024
	}
	mode := opts.Mode
	if mode == "" {
		mode = "redacted"
	}
	return &Recorder{
		redact:         opts.Redact,
		mode:           mode,
		debugScopes:    opts.DebugScopes,
		catalogMetrics: opts.CatalogMetrics,
		emitCatalogLog: opts.EmitCatalogLog,
		ring:           make([]Record, ringSize),
		byAction:       make(map[string]int64),
		byStatus:       make(map[int]int64),
		byDomain:       make(map[string]int64),
		byRule:         make(map[string]int64),
		byCatalog:      make(map[string]int64),
		byCatalogClass: make(map[catalogMetricKey]int64),
	}
}

// SetRedact toggles redaction (reload-safe log.redact).
func (r *Recorder) SetRedact(v bool) {
	r.mu.Lock()
	r.redact = v
	r.mu.Unlock()
}

// SetOptions updates logging mode/redaction on reload.
func (r *Recorder) SetOptions(opts Options) {
	r.mu.Lock()
	r.redact = opts.Redact
	if opts.Mode == "" {
		r.mode = "redacted"
	} else {
		r.mode = opts.Mode
	}
	r.debugScopes = opts.DebugScopes
	r.catalogMetrics = opts.CatalogMetrics
	r.emitCatalogLog = opts.EmitCatalogLog
	r.mu.Unlock()
}

// Log records rec: append to the ring, bump counters, and emit a JSON log line
// (redacted when enabled — masks query values so Loki never receives raw
// identifiers, design doc §Loki redact).
func (r *Recorder) Log(rec Record) {
	r.mu.Lock()
	redact := r.redact
	mode := r.mode
	emitCatalogLog := r.emitCatalogLog
	stored := r.applyPolicyLocked(rec)
	r.ring[r.next] = stored
	r.next = (r.next + 1) % len(r.ring)
	if r.next == 0 {
		r.full = true
	}
	r.byAction[rec.Action]++
	r.byStatus[rec.Status]++
	if rec.Domain != "" {
		r.byDomain[rec.Domain]++
	}
	if rec.Rule != "" {
		r.byRule[rec.Rule]++
	}
	if rec.CatalogID != "" {
		r.byCatalog[rec.CatalogID]++
	}
	if r.catalogMetrics && hasCatalogClass(rec) {
		r.byCatalogClass[catalogMetricKey{
			Category:     nonempty(rec.Category, "unknown"),
			Risk:         nonempty(rec.Risk, "unknown"),
			Verified:     boolString(rec.Verified),
			ReviewStatus: nonempty(rec.ReviewStatus, "unknown"),
			SourceType:   nonempty(rec.CatalogSource, "unknown"),
		}]++
	}
	r.total++
	r.bytesTotal += rec.Bytes
	r.mu.Unlock()

	if mode == "off" {
		return
	}
	logged := stored
	if !emitCatalogLog {
		clearCatalogFields(&logged)
	}
	if redact && (mode == "" || mode == "redacted") {
		logged.Path = RedactURL(logged.Path)
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
	if r.redact || r.mode == "stats" || r.mode == "off" {
		for i := range buffered {
			buffered[i] = r.applyPolicyLocked(buffered[i])
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
	if r.redact || r.mode == "stats" || r.mode == "off" {
		for i := range out {
			out[i] = r.applyPolicyLocked(out[i])
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

	if r.catalogMetrics {
		sb.WriteString("# HELP mirage_chaff_catalog_requests_total Requests by low-cardinality catalog classification.\n")
		sb.WriteString("# TYPE mirage_chaff_catalog_requests_total counter\n")
		keys := make([]catalogMetricKey, 0, len(r.byCatalogClass))
		for k := range r.byCatalogClass {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Category+keys[i].Risk+keys[i].ReviewStatus < keys[j].Category+keys[j].Risk+keys[j].ReviewStatus
		})
		for _, k := range keys {
			sb.WriteString(`mirage_chaff_catalog_requests_total{category="` + prom(k.Category) + `",risk="` + prom(k.Risk) + `",verified="` + prom(k.Verified) + `",review_status="` + prom(k.ReviewStatus) + `",source_type="` + prom(k.SourceType) + `"}`)
			sb.WriteByte(' ')
			sb.WriteString(itoa(r.byCatalogClass[k]) + "\n")
		}
	}
}

// Analytics returns bounded admin-facing summaries from retained counters.
func (r *Recorder) Analytics() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"total":       r.total,
		"bytes":       r.bytesTotal,
		"log_mode":    r.mode,
		"by_action":   copyStringMap(r.byAction),
		"top_domains": topStringMap(r.byDomain, 50),
		"top_rules":   topStringMap(r.byRule, 50),
		"top_catalog": topStringMap(r.byCatalog, 50),
	}
}

func (r *Recorder) applyPolicyLocked(rec Record) Record {
	rec.RedactionMode = r.mode
	switch r.mode {
	case "off":
		rec.Path = ""
	case "stats":
		rec.Path = ""
		rec.Method = ""
	case "full":
		return rec
	case "debug":
		if r.debugMatch(rec) {
			return rec
		}
		rec.Path = RedactURL(rec.Path)
	default:
		if r.redact {
			rec.Path = RedactURL(rec.Path)
		}
	}
	return rec
}

func (r *Recorder) debugMatch(rec Record) bool {
	now := time.Now()
	for _, s := range r.debugScopes {
		if !s.Expires.IsZero() && now.After(s.Expires) {
			continue
		}
		if s.Domain != "" && rec.Domain != s.Domain && !strings.HasSuffix(rec.Domain, "."+s.Domain) {
			continue
		}
		if s.Client != "" && s.Client != rec.Client {
			continue
		}
		return true
	}
	return false
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

type kvCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

func copyStringMap(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func topStringMap(in map[string]int64, n int) []kvCount {
	out := make([]kvCount, 0, len(in))
	for k, v := range in {
		out = append(out, kvCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func hasCatalogClass(rec Record) bool {
	return rec.Category != "" || rec.Risk != "" || rec.ReviewStatus != "" || rec.CatalogSource != ""
}

func nonempty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func prom(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	return strings.ReplaceAll(v, `"`, `\"`)
}

func clearCatalogFields(rec *Record) {
	rec.CatalogID = ""
	rec.CatalogSource = ""
	rec.Category = ""
	rec.Layer = ""
	rec.ResourceType = ""
	rec.Risk = ""
	rec.Confidence = ""
	rec.ReviewStatus = ""
	rec.Verified = false
	rec.RewriteState = ""
	rec.CNAMETarget = ""
	rec.TrackerVendor = ""
	rec.CNAMEConfidence = ""
	rec.ExpectedCatalog = ""
	rec.StubTemplate = ""
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
