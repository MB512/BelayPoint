package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/auth"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// fakeVault implements Vault with a plain password.
type fakeVault struct {
	mu       sync.Mutex
	password []byte // nil: not initialized
	sealed   bool
	secrets  []string // names for Has
	// seen are the password slices passed in, to check they get zeroed.
	seen [][]byte
}

func (v *fakeVault) Initialized() bool { v.mu.Lock(); defer v.mu.Unlock(); return v.password != nil }
func (v *fakeVault) Sealed() bool      { v.mu.Lock(); defer v.mu.Unlock(); return v.sealed }
func (v *fakeVault) Seal()             { v.mu.Lock(); defer v.mu.Unlock(); v.sealed = true }

func (v *fakeVault) Create(pw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = append(v.seen, pw)
	if v.password != nil {
		return vault.ErrInitialized
	}
	v.password, v.sealed = bytes.Clone(pw), false
	return nil
}

func (v *fakeVault) Unseal(pw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen = append(v.seen, pw)
	if v.password == nil {
		return vault.ErrNotInitialized
	}
	if !bytes.Equal(pw, v.password) {
		return vault.ErrWrongPassword
	}
	v.sealed = false
	return nil
}

// recorder collects audit events.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) Audit(_ context.Context, event, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

// ListAudit returns the recorded events newest first, with details
// "<script>" to check escaping. Paging is ignored.
func (r *recorder) ListAudit(_ context.Context, limit int, _ int64) ([]store.AuditEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.AuditEntry
	for i := len(r.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, store.AuditEntry{ID: int64(i + 1), Time: time.Unix(0, 0), Event: r.events[i], Details: "<script>"})
	}
	return out, nil
}

func (r *recorder) has(event string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.events, event)
}

// fakeScanner counts rescans.
type fakeScanner struct {
	mu      sync.Mutex
	rescans int
}

func (f *fakeScanner) Rescan() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rescans++
	return true
}

func (f *fakeScanner) Scanning() bool { return false }

func (v *fakeVault) Has(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Contains(v.secrets, name)
}

type testEnv struct {
	h        http.Handler
	vault    *fakeVault
	audit    *recorder
	limiter  *auth.Limiter
	store    *store.Store
	scanner  *fakeScanner
	reposDir string
}

const testSetupCode = "ABCD-EFGH-JKMN-PQRS"

func newEnv(t *testing.T, caPEM []byte, initialized bool) *testEnv {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e := &testEnv{
		vault: &fakeVault{}, audit: &recorder{}, limiter: auth.NewLimiter(time.Now),
		store: db, scanner: &fakeScanner{}, reposDir: t.TempDir(),
	}
	code := testSetupCode
	if initialized {
		e.vault.password, e.vault.sealed, code = []byte("correct horse battery"), true, ""
	}
	e.h = New(Options{
		Version:       "test",
		CAPEM:         caPEM,
		CAFingerprint: "AB:CD",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Vault:         e.vault,
		Sessions:      auth.NewSessions(time.Hour, time.Now),
		Limiter:       e.limiter,
		Audit:         e.audit,
		AuditLog:      e.audit,
		Repos:         db,
		Scanner:       e.scanner,
		ReposDir:      e.reposDir,
		Location:      time.UTC,
		SetupCode:     code,
	})
	return e
}

func handler(t *testing.T, caPEM []byte) http.Handler { return newEnv(t, caPEM, true).h }

func get(h http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHealthz(t *testing.T) {
	w := get(handler(t, nil), "/healthz", nil)
	if w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
}

func TestCADownload(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\n")
	w := get(handler(t, pem), "/ca.crt", nil)
	if w.Code != http.StatusOK || w.Body.String() != string(pem) {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Errorf("Content-Type %q", ct)
	}
	if w := get(handler(t, nil), "/ca.crt", nil); w.Code != http.StatusNotFound {
		t.Errorf("without CA: %d", w.Code)
	}
}

func TestLoginPageShowsFingerprint(t *testing.T) {
	w := get(handler(t, []byte("x")), "/login", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "AB:CD") {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
}

func TestStaticCSS(t *testing.T) {
	w := get(handler(t, nil), "/static/style.css", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/css") {
		t.Errorf("got %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestSecurityHeaders(t *testing.T) {
	w := get(handler(t, nil), "/login", nil)
	for _, h := range []string{"Content-Security-Policy", "Cache-Control", "X-Content-Type-Options", "X-Frame-Options"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set (breaks certificate exceptions)")
	}
}

func TestCloudflareRejected(t *testing.T) {
	w := get(handler(t, nil), "/healthz", map[string]string{"Cf-Ray": "abc"})
	if w.Code != http.StatusForbidden {
		t.Errorf("got %d", w.Code)
	}
}
