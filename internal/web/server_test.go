package web

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/MB512/belaypoint/internal/htpasswd"
	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/notify"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// fakeVault implements Vault with a plain password.
type fakeVault struct {
	mu       sync.Mutex
	password []byte // nil: not initialized
	sealed   bool
	secrets  []string // names for Has
	values   map[string][]byte
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

func (v *fakeVault) SetSecret(name string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.sealed {
		return vault.ErrSealed
	}
	if v.values == nil {
		v.values = map[string][]byte{}
	}
	v.values[name] = bytes.Clone(value)
	v.seen = append(v.seen, value)
	if !slices.Contains(v.secrets, name) {
		v.secrets = append(v.secrets, name)
	}
	return nil
}

func (v *fakeVault) DeleteSecret(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.values, name)
	v.secrets = slices.DeleteFunc(v.secrets, func(n string) bool { return n == name })
	return nil
}

// fakeRestic accepts one password for every repository.
type fakeRestic struct {
	mu       sync.Mutex
	password string
	dirs     []string
	seen     [][]byte
}

func (f *fakeRestic) CatConfig(_ context.Context, dir string, pw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs = append(f.dirs, dir)
	f.seen = append(f.seen, pw)
	if string(pw) != f.password {
		return fmt.Errorf("restic cat failed: %w", restic.ErrWrongPassword)
	}
	return nil
}

// fakeJobs records submitted jobs.
type fakeJobs struct {
	mu        sync.Mutex
	submitted []string
	previews  []string
	busy      map[string]bool
	err       error
	keepAll   bool // PreviewForget removes nothing
}

func (f *fakeJobs) Submit(_ context.Context, repo string, typ jobs.Type, _ jobs.Trigger) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.submitted = append(f.submitted, string(typ)+" "+repo)
	return int64(len(f.submitted)), nil
}

func (f *fakeJobs) SubmitPrune(_ context.Context, repo, maxUnused string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.submitted = append(f.submitted, strings.TrimSpace("prune "+repo+" "+maxUnused))
	return int64(len(f.submitted)), nil
}

func (f *fakeJobs) SubmitCheck(_ context.Context, repo, subset string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.submitted = append(f.submitted, strings.TrimSpace("check "+repo+" "+subset))
	return int64(len(f.submitted)), nil
}

func (f *fakeJobs) PreviewForget(_ context.Context, repo string, p restic.Policy) ([]restic.PassResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.previews = append(f.previews, repo+" "+p.String())
	t0 := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	if f.keepAll {
		return []restic.PassResult{{Groups: []restic.ForgetGroup{{Host: "pc", Keep: []restic.Snapshot{{ShortID: "keep0001", Time: t0}}}}}}, nil
	}
	var res []restic.PassResult
	for _, r := range p.TagRules {
		res = append(res, restic.PassResult{Tag: r.Tag, Groups: []restic.ForgetGroup{{
			Host: "pc", Remove: []restic.Snapshot{{ShortID: "prestop1", Time: t0, Tags: []string{r.Tag}}},
		}}})
	}
	return append(res, restic.PassResult{Groups: []restic.ForgetGroup{{
		Host: "pc<1>", Paths: []string{"/home"},
		Keep:   []restic.Snapshot{{ShortID: "keep0001", Time: t0}},
		Remove: []restic.Snapshot{{ShortID: "gone0001", Time: t0}, {ShortID: "gone0002", Time: t0, Tags: []string{"daily"}}},
	}}}), nil
}

// fakeSchedule counts reloads.
type fakeSchedule struct {
	mu      sync.Mutex
	reloads int
}

func (f *fakeSchedule) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return nil
}
func (f *fakeSchedule) Next(repo string) time.Time {
	if repo == "alice/main" {
		return time.Date(2026, 11, 29, 3, 30, 0, 0, time.UTC)
	}
	return time.Time{}
}

func (f *fakeJobs) Busy(repo string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.busy[repo] }

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
	restic   *fakeRestic
	jobs     *fakeJobs
	schedule *fakeSchedule
	notifier *fakeNotifier
	reposDir string
	logDir   string
	opts     Options
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
		store: db, scanner: &fakeScanner{}, restic: &fakeRestic{password: "repo secret"}, jobs: &fakeJobs{busy: map[string]bool{}}, logDir: t.TempDir(), schedule: &fakeSchedule{}, reposDir: t.TempDir(),
	}
	code := testSetupCode
	if initialized {
		e.vault.password, e.vault.sealed, code = []byte("correct horse battery"), true, ""
	}
	e.notifier = &fakeNotifier{configured: true}
	e.opts = Options{
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
		Users:         &htpasswd.File{Path: filepath.Join(e.reposDir, ".htpasswd")},
		Scanner:       e.scanner,
		Restic:        e.restic,
		Jobs:          e.jobs,
		JobList:       db,
		JobLogDir:     e.logDir,
		Policies:      db,
		Plans:         db,
		Flags:         db,
		Notifier:      e.notifier,
		Settings:      db,
		Schedule:      e.schedule,
		ReposDir:      e.reposDir,
		Location:      time.UTC,
		SetupCode:     code,
	}
	e.h = New(e.opts)
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

func TestStaticIcons(t *testing.T) {
	h := handler(t, nil)
	for path, ctype := range map[string]string{
		"/static/favicon.svg":          "image/svg+xml",
		"/static/favicon.ico":          "image/",
		"/static/apple-touch-icon.png": "image/png",
	} {
		w := get(h, path, nil)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), ctype) {
			t.Errorf("%s: got %d %q", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
	// The login page uses the layout too: it must link the icons.
	if body := get(handler(t, []byte("x")), "/login", nil).Body.String(); !strings.Contains(body, `href="/static/favicon.svg"`) {
		t.Error("pages must link the favicon")
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

// fakeNotifier records notifications.
type fakeNotifier struct {
	mu         sync.Mutex
	configured bool
	sendErr    error
	sent       []notify.Message
	settings   notify.SettingStore
}

func (f *fakeNotifier) Configured() bool { return f.configured }
func (f *fakeNotifier) Enabled(ctx context.Context, e notify.Event) bool {
	if f.settings == nil {
		return f.configured
	}
	return f.configured && notify.EnabledIn(f.settings)(ctx, e)
}
func (f *fakeNotifier) Notify(ctx context.Context, m notify.Message) {
	if !f.Enabled(ctx, m.Event) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
}
func (f *fakeNotifier) SendNow(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, m)
	return nil
}
