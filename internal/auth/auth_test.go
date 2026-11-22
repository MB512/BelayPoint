package auth

import (
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source for tests.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestSessionLifecycle(t *testing.T) {
	c := newClock()
	s := NewSessions(time.Hour, c.Now)
	token, sess, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 43 || sess.CSRF == "" || sess.CSRF == token {
		t.Fatalf("token %q, csrf %q", token, sess.CSRF)
	}
	got, ok := s.Lookup(token)
	if !ok || got.CSRF != sess.CSRF {
		t.Fatalf("Lookup = %+v, %v", got, ok)
	}
	for _, bad := range []string{"", "x", token + "x"} {
		if _, ok := s.Lookup(bad); ok {
			t.Errorf("Lookup(%q) succeeded", bad)
		}
	}

	// Sliding expiry: every use extends the lifetime.
	for range 3 {
		c.Advance(50 * time.Minute)
		if _, ok := s.Lookup(token); !ok {
			t.Fatal("session expired despite use")
		}
	}
	c.Advance(61 * time.Minute)
	if _, ok := s.Lookup(token); ok {
		t.Error("session alive after TTL without use")
	}

	t1, _, _ := s.Create()
	t2, _, _ := s.Create()
	s.Delete(t1)
	if _, ok := s.Lookup(t1); ok {
		t.Error("deleted session alive")
	}
	if _, ok := s.Lookup(t2); !ok {
		t.Error("Delete removed another session")
	}
	s.DeleteAll()
	if s.Count() != 0 {
		t.Errorf("Count after DeleteAll = %d", s.Count())
	}
}

func TestSessionTokensStoredAsHash(t *testing.T) {
	s := NewSessions(time.Hour, time.Now)
	token, _, _ := s.Create()
	if _, ok := s.m[sha256.Sum256([]byte(token))]; !ok || len(s.m) != 1 {
		t.Error("session not keyed by the SHA-256 of its token")
	}
}

func TestSessionLimit(t *testing.T) {
	c := newClock()
	s := NewSessions(time.Hour, c.Now)
	first, _, _ := s.Create()
	c.Advance(time.Second)
	second, _, _ := s.Create()
	for range MaxSessions - 2 {
		c.Advance(time.Second)
		_, _, _ = s.Create()
	}
	c.Advance(time.Second)
	s.Lookup(first) // first is now the most recently used, second the oldest
	_, _, _ = s.Create()
	if s.Count() != MaxSessions {
		t.Errorf("Count = %d, want %d", s.Count(), MaxSessions)
	}
	if _, ok := s.Lookup(second); ok {
		t.Error("least recently used session not dropped")
	}
	if _, ok := s.Lookup(first); !ok {
		t.Error("recently used session dropped")
	}
}

func TestLimiter(t *testing.T) {
	c := newClock()
	l := NewLimiter(c.Now)
	fail := func() time.Duration {
		t.Helper()
		if _, ok := l.Begin(); !ok {
			t.Fatal("Begin refused")
		}
		return l.End(false)
	}
	for i := range FreeFailures {
		if d := fail(); d != 0 {
			t.Fatalf("failure %d locked for %v", i+1, d)
		}
	}
	wantLockouts := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute,
		4 * time.Minute, 8 * time.Minute, MaxLockout, MaxLockout}
	for i, want := range wantLockouts {
		if d := fail(); d != want {
			t.Fatalf("failure %d: lockout %v, want %v", FreeFailures+1+i, d, want)
		}
		if wait, ok := l.Begin(); ok || wait != want {
			t.Fatalf("Begin during lockout = %v, %v", wait, ok)
		}
		c.Advance(want - time.Second)
		if _, ok := l.Begin(); ok {
			t.Fatal("Begin allowed before lockout ended")
		}
		c.Advance(time.Second)
	}

	if _, ok := l.Begin(); !ok {
		t.Fatal("Begin refused after lockout")
	}
	l.End(true)
	if l.Failures() != 0 {
		t.Errorf("Failures after success = %d", l.Failures())
	}
	if d := fail(); d != 0 {
		t.Errorf("first failure after success locked for %v", d)
	}
}

func TestLimiterOneAttemptAtATime(t *testing.T) {
	l := NewLimiter(time.Now)
	if _, ok := l.Begin(); !ok {
		t.Fatal("first Begin refused")
	}
	if wait, ok := l.Begin(); ok || wait != 0 {
		t.Errorf("concurrent Begin = %v, %v; want refused without lockout", wait, ok)
	}
	l.End(true)
	if _, ok := l.Begin(); !ok {
		t.Error("Begin refused after End")
	}
}

func TestSetupCode(t *testing.T) {
	code, err := NewSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 19 || strings.Count(code, "-") != 3 || strings.ContainsAny(code, "01ILO") {
		t.Errorf("code %q", code)
	}
	other, _ := NewSetupCode()
	if other == code {
		t.Error("two codes are equal")
	}
	tests := []struct {
		typed string
		want  bool
	}{
		{code, true},
		{strings.ToLower(code), true},
		{" " + strings.ReplaceAll(code, "-", " ") + " ", true},
		{strings.ReplaceAll(code, "-", ""), true},
		{code[:18], false},
		{code + "X", false},
		{other, false},
		{"", false},
	}
	for _, tt := range tests {
		if got := SetupCodeMatches(code, tt.typed); got != tt.want {
			t.Errorf("SetupCodeMatches(%q) = %v, want %v", tt.typed, got, tt.want)
		}
	}
	if SetupCodeMatches("", "") {
		t.Error("empty expected code matched")
	}
}
