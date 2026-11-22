// Package auth holds the pieces of the login that do not depend on HTTP:
// in-memory sessions, the failed-login limiter and the first-start setup
// code (see rule 6 in docs/security.md). Checking the password itself is
// the vault's job: logging in means unsealing.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// MaxSessions bounds the number of concurrent sessions; creating one more
// drops the least recently used.
const MaxSessions = 16

// Session is what a valid session token gives access to.
type Session struct {
	// CSRF is the token every state-changing request of this session must
	// carry (form field or header).
	CSRF    string
	Created time.Time
}

type entry struct {
	Session
	lastSeen time.Time
}

// Sessions keeps sessions in memory only, so a restart logs everybody out.
// Tokens are stored as SHA-256 hashes: a memory dump of the map alone does
// not yield a usable cookie. Safe for concurrent use.
type Sessions struct {
	ttl time.Duration
	now func() time.Time

	mu sync.Mutex
	m  map[[sha256.Size]byte]*entry
}

// NewSessions returns an empty store. A session expires ttl after its last
// use (sliding expiry). now is time.Now outside tests.
func NewSessions(ttl time.Duration, now func() time.Time) *Sessions {
	return &Sessions{ttl: ttl, now: now, m: map[[sha256.Size]byte]*entry{}}
}

// Create starts a session and returns its token (for the cookie).
func (s *Sessions) Create() (string, Session, error) {
	token, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	now := s.now()
	e := &entry{Session: Session{CSRF: csrf, Created: now}, lastSeen: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if len(s.m) >= MaxSessions {
		s.dropOldest()
	}
	s.m[sha256.Sum256([]byte(token))] = e
	return token, e.Session, nil
}

// Lookup returns the session for token and extends its lifetime.
func (s *Sessions) Lookup(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	key := sha256.Sum256([]byte(token))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok {
		return Session{}, false
	}
	if now.Sub(e.lastSeen) > s.ttl {
		delete(s.m, key)
		return Session{}, false
	}
	e.lastSeen = now
	return e.Session, true
}

// Delete ends the session of token (logout). Unknown tokens are ignored.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sha256.Sum256([]byte(token)))
}

// DeleteAll ends every session (seal).
func (s *Sessions) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.m)
}

// Count returns the number of unexpired sessions.
func (s *Sessions) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	return len(s.m)
}

// sweep drops expired sessions. Callers hold mu.
func (s *Sessions) sweep(now time.Time) {
	for k, e := range s.m {
		if now.Sub(e.lastSeen) > s.ttl {
			delete(s.m, k)
		}
	}
}

// dropOldest removes the least recently used session. Callers hold mu.
func (s *Sessions) dropOldest() {
	var oldest [sha256.Size]byte
	var found *entry
	for k, e := range s.m {
		if found == nil || e.lastSeen.Before(found.lastSeen) {
			oldest, found = k, e
		}
	}
	if found != nil {
		delete(s.m, oldest)
	}
}

// randomToken returns 256 random bits, base64url-encoded.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
