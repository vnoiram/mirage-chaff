package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Role is an RBAC role name.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// Capabilities per role (design doc RBAC table).
var roleCaps = map[Role]map[string]bool{
	RoleAdmin: capsSet(
		"dashboard.view", "traffic.view", "traffic.view_full", "policy.view", "policy.edit",
		"catalog.view", "catalog.edit", "mimic.view", "mimic.edit", "config.view", "config.edit",
		"apply.reload", "agh.manage", "killswitch.execute", "users.manage", "audit.view", "allow.temp",
	),
	RoleEditor: capsSet(
		"dashboard.view", "traffic.view", "policy.view", "policy.edit", "catalog.view", "catalog.edit",
		"mimic.view", "mimic.edit", "config.view", "apply.reload", "allow.temp",
	),
	RoleViewer: capsSet(
		"dashboard.view", "traffic.view", "policy.view", "catalog.view", "mimic.view", "config.view", "audit.view",
	),
}

func capsSet(caps ...string) map[string]bool {
	m := make(map[string]bool, len(caps))
	for _, c := range caps {
		m[c] = true
	}
	return m
}

// Can reports whether role has capability.
func Can(role Role, capability string) bool {
	caps, ok := roleCaps[role]
	return ok && caps[capability]
}

// User is an admin account.
type User struct {
	Username   string    `json:"username"`
	Hash       string    `json:"hash"` // argon2id encoded
	Role       Role      `json:"role"`
	Disabled   bool      `json:"disabled"`
	MustChange bool      `json:"must_change"` // force password change on next login
	Created    time.Time `json:"created"`
}

// AuditEntry records a change operation (actor + time + what).
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

// Store is a JSON-file-backed user + audit store (0600, git-ignored). SQLite is
// the documented production target; a single-file JSON store keeps the daemon
// dependency-light and is sufficient for the small admin account set.
type Store struct {
	path string
	mu   sync.Mutex
	data storeData
}

type storeData struct {
	Users []User       `json:"users"`
	Audit []AuditEntry `json:"audit"`
}

// OpenStore loads (or creates) the store at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("parse admin store: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// UserCount returns the number of accounts.
func (s *Store) UserCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data.Users)
}

// Get returns a user by name.
func (s *Store) Get(username string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.data.Users {
		if u.Username == username {
			return u, true
		}
	}
	return User{}, false
}

// List returns all users (without hashes).
func (s *Store) List() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, len(s.data.Users))
	copy(out, s.data.Users)
	for i := range out {
		out[i].Hash = ""
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Upsert creates or replaces a user.
func (s *Store) Upsert(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.data.Users {
		if e.Username == u.Username {
			if u.Hash == "" {
				u.Hash = e.Hash // preserve existing password when not changing it
			}
			s.data.Users[i] = u
			return s.save()
		}
	}
	if u.Created.IsZero() {
		u.Created = time.Now()
	}
	s.data.Users = append(s.data.Users, u)
	return s.save()
}

// Delete removes a user.
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.data.Users[:0]
	for _, u := range s.data.Users {
		if u.Username != username {
			out = append(out, u)
		}
	}
	s.data.Users = out
	return s.save()
}

// SetPassword sets a new password hash and clears MustChange.
func (s *Store) SetPassword(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.data.Users {
		if u.Username == username {
			s.data.Users[i].Hash = HashPassword(password)
			s.data.Users[i].MustChange = false
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", username)
}

// Audit appends an audit entry (bounded to the most recent 5000) and also emits
// it to the process log with a SECURITY tag, so the fleet's Wazuh/SOC pipeline
// can ingest admin/security events from journald (design doc §9).
func (s *Store) Audit(actor, action, detail string) {
	e := AuditEntry{Time: time.Now(), Actor: actor, Action: action, Detail: detail}
	s.mu.Lock()
	s.data.Audit = append(s.data.Audit, e)
	if len(s.data.Audit) > 5000 {
		s.data.Audit = s.data.Audit[len(s.data.Audit)-5000:]
	}
	_ = s.save()
	s.mu.Unlock()

	if b, err := json.Marshal(e); err == nil {
		log.Printf("SECURITY mirage-chaff-audit %s", b)
	}
}

// AuditLog returns the most recent n audit entries (newest first).
func (s *Store) AuditLog(n int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEntry, len(s.data.Audit))
	copy(out, s.data.Audit)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// --- argon2id password hashing ---

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// dummyArgonHash is a valid encoded hash for a password no one has, verified
// against on login for unknown/disabled accounts so timing does not leak whether
// an account exists (see handleLogin).
var dummyArgonHash = HashPassword("mirage-chaff-nonexistent-account")

// HashPassword returns an encoded argon2id hash string.
func HashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword checks password against an encoded argon2id hash.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}
	var mem, tm, th int
	if _, err := fmt.Sscanf(parts[1]+" "+parts[2]+" "+parts[3], "%d %d %d", &mem, &tm, &th); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(tm), uint32(mem), uint8(th), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
