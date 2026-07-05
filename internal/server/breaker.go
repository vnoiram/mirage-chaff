package server

import (
	"log"
	"sync"
	"time"
)

// breaker is a per-domain circuit breaker: after too many consecutive upstream
// failures for a domain, it opens and the server serves a safe stub directly
// (skipping the failing origin) until a cooldown elapses. This prevents a broken
// mimic/forward origin from failing worse than a plain block (design doc
// "回路遮断 / circuit breaker").
type breaker struct {
	threshold int
	cooldown  time.Duration

	mu    sync.Mutex
	state map[string]*breakerState
}

type breakerState struct {
	failures  int
	openUntil time.Time
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &breaker{threshold: threshold, cooldown: cooldown, state: map[string]*breakerState{}}
}

// Allow reports whether a request to domain's origin should be attempted.
func (b *breaker) Allow(domain string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state[domain]
	if s == nil {
		return true
	}
	if s.openUntil.IsZero() {
		return true
	}
	if time.Now().Before(s.openUntil) {
		return false
	}
	// Cooldown elapsed: half-open — allow one probe and reset the window.
	s.openUntil = time.Time{}
	s.failures = 0
	return true
}

// RecordSuccess clears the failure count for domain.
func (b *breaker) RecordSuccess(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.state[domain]; s != nil {
		s.failures = 0
		s.openUntil = time.Time{}
	}
}

// RecordFailure increments the failure count and opens the breaker at threshold.
func (b *breaker) RecordFailure(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state[domain]
	if s == nil {
		s = &breakerState{}
		b.state[domain] = s
	}
	s.failures++
	if s.failures >= b.threshold && s.openUntil.IsZero() {
		s.openUntil = time.Now().Add(b.cooldown)
		// Log once per open transition (naturally bounded), rather than tracking a
		// per-domain "logged" flag that would grow without bound.
		log.Printf("circuit breaker open for %s (%d consecutive failures); serving safe stub for %s",
			domain, s.failures, b.cooldown)
	}
}

// Open reports whether the breaker is currently open for domain (for metrics/UI).
func (b *breaker) Open(domain string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state[domain]
	return s != nil && !s.openUntil.IsZero() && time.Now().Before(s.openUntil)
}
