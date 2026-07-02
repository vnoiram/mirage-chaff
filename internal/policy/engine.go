package policy

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Engine holds the live ruleset (hot-swappable) and aggregates requests that hit
// the default (no rule matched) so operators can see which domains/paths are
// candidates for a new curated rule (design doc "curation 支援").
type Engine struct {
	rs        atomic.Pointer[Ruleset]
	unmatched *aggregator
}

// NewEngine wraps an initial ruleset.
func NewEngine(rs *Ruleset) *Engine {
	e := &Engine{unmatched: newAggregator(10000)}
	e.rs.Store(rs)
	return e
}

// Swap atomically replaces the ruleset (used on reload after validation).
func (e *Engine) Swap(rs *Ruleset) { e.rs.Store(rs) }

// Ruleset returns the current ruleset.
func (e *Engine) Ruleset() *Ruleset { return e.rs.Load() }

// Decide matches a request and records it in the unmatched aggregator when the
// default was used.
func (e *Engine) Decide(domain, path, method string) Decision {
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

// aggregator counts unmatched (domain, path) pairs with a bounded map.
type aggregator struct {
	mu   sync.Mutex
	max  int
	hits map[string]*UnmatchedEntry
}

func newAggregator(max int) *aggregator {
	return &aggregator{max: max, hits: make(map[string]*UnmatchedEntry)}
}

func (a *aggregator) record(domain, path string) {
	key := domain + " " + path
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.hits[key]; ok {
		e.Count++
		e.Last = time.Now()
		return
	}
	if len(a.hits) >= a.max {
		// Bounded: drop the least-recently-seen entry to make room.
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range a.hits {
			if first || e.Last.Before(oldest) {
				oldest, oldestKey, first = e.Last, k, false
			}
		}
		delete(a.hits, oldestKey)
	}
	a.hits[key] = &UnmatchedEntry{Domain: domain, Path: path, Count: 1, Last: time.Now()}
}

func (a *aggregator) top(n int) []UnmatchedEntry {
	a.mu.Lock()
	out := make([]UnmatchedEntry, 0, len(a.hits))
	for _, e := range a.hits {
		out = append(out, *e)
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
