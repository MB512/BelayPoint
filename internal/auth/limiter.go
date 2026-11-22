package auth

import (
	"sync"
	"time"
)

// Limiter parameters (docs/security.md, rule 6).
const (
	FreeFailures = 5
	FirstLockout = 15 * time.Second
	MaxLockout   = 15 * time.Minute
)

// Limiter slows down password guessing. It is global, not per client
// address: there is one account, and attempts from many addresses must not
// multiply the guessing rate. Only one attempt runs at a time; each costs
// one argon2id derivation.
//
// After FreeFailures failed attempts, every further failure locks the
// login for FirstLockout, doubling up to MaxLockout. A success resets it.
// State is in memory only.
type Limiter struct {
	now func() time.Time

	mu       sync.Mutex
	failures int
	until    time.Time
	busy     bool
}

// NewLimiter returns a limiter; now is time.Now outside tests.
func NewLimiter(now func() time.Time) *Limiter {
	return &Limiter{now: now}
}

// Begin reserves the one attempt slot. If it returns ok == false, the
// caller must reject the attempt without checking the password; wait is
// the remaining lockout (zero if another attempt is just running).
// Otherwise the caller must call End or Abort exactly once.
func (l *Limiter) Begin() (wait time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.busy {
		return 0, false
	}
	if d := l.until.Sub(l.now()); d > 0 {
		return d, false
	}
	l.busy = true
	return 0, true
}

// End records the result of the attempt started with Begin and returns the
// lockout that now applies (zero if none).
func (l *Limiter) End(success bool) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.busy = false
	if success {
		l.failures = 0
		l.until = time.Time{}
		return 0
	}
	l.failures++
	if l.failures <= FreeFailures {
		return 0
	}
	d := FirstLockout
	for i := FreeFailures + 1; i < l.failures && d < MaxLockout; i++ {
		d *= 2
	}
	d = min(d, MaxLockout)
	l.until = l.now().Add(d)
	return d
}

// Abort ends the attempt started with Begin without counting it, for
// requests rejected before the secret was checked (e.g. a malformed form).
func (l *Limiter) Abort() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.busy = false
}

// Failures returns the number of failures since the last success.
func (l *Limiter) Failures() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures
}
