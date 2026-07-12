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
}

type lockState struct {
	failures  int
	lockUntil time.Time
}

const (
	lockThreshold = 5
	lockDuration  = 5 * time.Minute
)

func newSessionManager(idleTimeout time.Duration) *sessionManager {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Minute
	}
	return &sessionManager{
		idleTimeout: idleTimeout,
		sessions:    map[string]*session{},
		locks:       map[string]*lockState{},
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
func (m *sessionManager) recordFailure(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.locks[username]
	if l == nil {
		l = &lockState{}
		m.locks[username] = l
	}
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
