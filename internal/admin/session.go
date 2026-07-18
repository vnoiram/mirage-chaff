package admin

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// session is a server-side session.
type session struct {
	id       string
	username string
	role     Role
	csrf     string
	expires  time.Time
}

// sessionManager holds server-side sessions and per-user login lockout state.
type sessionManager struct {
	idleTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*session
	locks    map[string]*lockState
	ipLocks  map[string]*ipState
}

type lockState struct {
	failures  int
	lockUntil time.Time
	lastSeen  time.Time
}

type ipState struct {
	failures  int
	lockUntil time.Time
}

const (
	lockThreshold = 5
	lockDuration  = 5 * time.Minute
	lockSweepAge  = 30 * time.Minute

	ipLockThreshold = 20
	ipLockDuration  = 15 * time.Minute
	ipLockMapMax    = 500
)

func newSessionManager(idleTimeout time.Duration) *sessionManager {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Minute
	}
	return &sessionManager{
		idleTimeout: idleTimeout,
		sessions:    map[string]*session{},
		locks:       map[string]*lockState{},
		ipLocks:     map[string]*ipState{},
	}
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// create starts a session for a user.
func (m *sessionManager) create(username string, role Role) *session {
	s := &session{
		id:       randToken(),
		username: username,
		role:     role,
		csrf:     randToken(),
		expires:  time.Now().Add(m.idleTimeout),
	}
	m.mu.Lock()
	m.sessions[s.id] = s
	m.mu.Unlock()
	return s
}

// get returns the session for id, refreshing its idle expiry, or nil.
func (m *sessionManager) get(id string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return nil
	}
	if time.Now().After(s.expires) {
		delete(m.sessions, id)
		return nil
	}
	s.expires = time.Now().Add(m.idleTimeout)
	return s
}

func (m *sessionManager) destroy(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// destroyUser drops all sessions for a username (on disable/delete/password reset).
func (m *sessionManager) destroyUser(username string) {
	m.mu.Lock()
	for id, s := range m.sessions {
		if s.username == username {
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
}

// locked reports whether username is currently locked out.
func (m *sessionManager) locked(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.locks[username]
	return l != nil && time.Now().Before(l.lockUntil)
}

// recordFailure bumps the failure count and locks after the threshold.
// It also opportunistically sweeps sub-threshold entries whose window has
// expired, so stale entries from users who failed < 5 times and never
// returned do not accumulate forever.
func (m *sessionManager) recordFailure(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, ls := range m.locks {
		if ls.lockUntil.IsZero() && time.Since(ls.lastSeen) > lockSweepAge {
			delete(m.locks, k)
		}
	}
	l := m.locks[username]
	if l == nil {
		l = &lockState{}
		m.locks[username] = l
	}
	l.lastSeen = time.Now()
	l.failures++
	if l.failures >= lockThreshold {
		l.lockUntil = time.Now().Add(lockDuration)
		l.failures = 0
	}
}

func (m *sessionManager) recordSuccess(username string) {
	m.mu.Lock()
	delete(m.locks, username)
	m.mu.Unlock()
}

// ipLocked reports whether the given client IP is currently rate-limited.
func (m *sessionManager) ipLocked(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.ipLocks[ip]
	return s != nil && time.Now().Before(s.lockUntil)
}

// recordIPFailure increments the per-IP failure counter and locks the IP
// after ipLockThreshold failures. The map is capped at ipLockMapMax entries
// to prevent unbounded growth under enumeration attacks.
func (m *sessionManager) recordIPFailure(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ipLocks[ip]; !ok && len(m.ipLocks) >= ipLockMapMax {
		return
	}
	s := m.ipLocks[ip]
	if s == nil {
		s = &ipState{}
		m.ipLocks[ip] = s
	}
	s.failures++
	if s.failures >= ipLockThreshold {
		s.lockUntil = time.Now().Add(ipLockDuration)
		s.failures = 0
	}
}
