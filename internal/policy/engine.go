package policy

import (
	"container/list"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Engine holds the live ruleset (hot-swappable) and aggregates requests that hit
// the default (no rule matched) so operators can see which domains/paths are
// candidates for a new curated rule (design doc "curation 支援").
//
// It also carries a temporary per-domain override layer (TTL'd) that the admin UI
// uses for the "pass this site through for N minutes" control (design doc C).
type Engine struct {
	rs        atomic.Pointer[Ruleset]
	unmatched *aggregator

	tmu   sync.Mutex
	temps map[string]tempRule
}

type tempRule struct {
	dec     Decision
	expires time.Time
}

// NewEngine wraps an initial ruleset.
func NewEngine(rs *Ruleset) *Engine {
	e := &Engine{unmatched: newAggregator(10000), temps: map[string]tempRule{}}
	e.rs.Store(rs)
	return e
}

// AddTempRule installs a temporary override for domain that expires after ttl.
// action/catalog are validated by the caller; typically forward-asis (pass the
// real site through) for a "temporary allow".
func (e *Engine) AddTempRule(domain, action, catalog string, ttl time.Duration) {
	e.tmu.Lock()
	e.temps[domain] = tempRule{dec: Decision{Action: action, Catalog: catalog, Rule: "temp:" + domain, Matched: true}, expires: time.Now().Add(ttl)}
	e.tmu.Unlock()
}

// TempRules returns the active (non-expired) temporary overrides.
func (e *Engine) TempRules() map[string]time.Time {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	out := map[string]time.Time{}
	now := time.Now()
	for d, t := range e.temps {
		if now.Before(t.expires) {
			out[d] = t.expires
		} else {
			delete(e.temps, d)
		}
	}
	return out
}

func (e *Engine) tempFor(domain string) (Decision, bool) {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	t, ok := e.temps[domain]
	if !ok {
		return Decision{}, false
	}
	if time.Now().After(t.expires) {
		delete(e.temps, domain)
		return Decision{}, false
	}
	return t.dec, true
}

// Swap atomically replaces the ruleset (used on reload after validation).
func (e *Engine) Swap(rs *Ruleset) { e.rs.Store(rs) }

// Ruleset returns the current ruleset.
func (e *Engine) Ruleset() *Ruleset { return e.rs.Load() }

// Decide matches a request and records it in the unmatched aggregator when the
// default was used. A live temporary override for the domain takes precedence.
func (e *Engine) Decide(domain, path, method string) Decision {
	if d, ok := e.tempFor(domain); ok {
		return d
	}
	d := e.rs.Load().Match(domain, path, method)
	if !d.Matched {
		e.unmatched.record(domain, path)
	}
	return d
}

// UnmatchedEntry is one aggregated unmatched (domain, path) with a hit count.
type UnmatchedEntry struct {
	Domain string
	Path   string
	Count  int64
	Last   time.Time
}

// UnmatchedTop returns the top-n unmatched entries by hit count.
func (e *Engine) UnmatchedTop(n int) []UnmatchedEntry { return e.unmatched.top(n) }

// aggregator counts unmatched (domain, path) pairs with a bounded LRU. Eviction
// is O(1): the intrusive list keeps entries in recency order (front = most
// recently seen), so record() never scans the whole set even when full — this
// path runs on every unmatched request, including high-cardinality junk traffic.
type aggregator struct {
	mu    sync.Mutex
	max   int
	ll    *list.List               // *UnmatchedEntry, front = most recently seen
	items map[string]*list.Element // key -> element
}

func newAggregator(max int) *aggregator {
	return &aggregator{max: max, ll: list.New(), items: make(map[string]*list.Element)}
}

func (a *aggregator) record(domain, path string) {
	key := domain + " " + path
	a.mu.Lock()
	defer a.mu.Unlock()
	if el, ok := a.items[key]; ok {
		e := el.Value.(*UnmatchedEntry)
		e.Count++
		e.Last = time.Now()
		a.ll.MoveToFront(el)
		return
	}
	if a.ll.Len() >= a.max {
		// Bounded: drop the least-recently-seen entry (list back) to make room.
		if back := a.ll.Back(); back != nil {
			old := back.Value.(*UnmatchedEntry)
			delete(a.items, old.Domain+" "+old.Path)
			a.ll.Remove(back)
		}
	}
	a.items[key] = a.ll.PushFront(&UnmatchedEntry{Domain: domain, Path: path, Count: 1, Last: time.Now()})
}

func (a *aggregator) top(n int) []UnmatchedEntry {
	a.mu.Lock()
	out := make([]UnmatchedEntry, 0, a.ll.Len())
	for el := a.ll.Front(); el != nil; el = el.Next() {
		out = append(out, *el.Value.(*UnmatchedEntry))
	}
	a.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
