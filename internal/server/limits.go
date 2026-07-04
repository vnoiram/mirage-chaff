package server

import (
	"sync"
	"time"
)

// rateLimiter is a simple token-bucket limiter for the intercept handler,
// enforcing resources.rate_limit (requests/second, burst = rate). A nil limiter
// (rate_limit <= 0) allows everything.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// newRateLimiter returns a limiter admitting perSec requests/second, or nil when
// perSec <= 0 (unlimited).
func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return nil
	}
	r := float64(perSec)
	return &rateLimiter{rate: r, burst: r, tokens: r, last: time.Now()}
}

// Allow reports whether a request may proceed, consuming one token if so. It is
// nil-safe: a nil limiter always allows.
func (l *rateLimiter) Allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	l.last = now
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}
