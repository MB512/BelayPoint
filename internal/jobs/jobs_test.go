package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// fakeSecrets is a vault with plain values.
type fakeSecrets struct {
	mu     sync.Mutex
	sealed bool
	values map[string][]byte
	given  [][]byte // copies handed out, to check they get zeroed
}

func (f *fakeSecrets) Sealed() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.sealed }
func (f *fakeSecrets) seal()        { f.mu.Lock(); defer f.mu.Unlock(); f.sealed = true }

func (f *fakeSecrets) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.values[name]
	return ok
}

func (f *fakeSecrets) Secret(name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return nil, vault.ErrSealed
	}
	v, ok := f.values[name]
	if !ok {
		return nil, vault.ErrNotFound
	}
	c := bytes.Clone(v)
	f.given = append(f.given, c)
	return c, nil
}

// fakeRunner lists snapshots; with block set it waits for release (or
// ctx) first.
type fakeRunner struct {
	mu       sync.Mutex
	block    bool
	started  chan string   // repo of each started call
	release  chan struct{} // closed to let blocked calls finish
	err      error
	active   int
	peak     int
	seenPW   []string
	steps    []string
	pruneErr error
}

func newRunner(block bool) *fakeRunner {
	return &fakeRunner{block: block, started: make(chan string, 16), release: make(chan struct{})}
}

func (f *fakeRunner) CatConfig(context.Context, string, []byte) error { return nil }

func (f *fakeRunner) ForgetPreview(_ context.Context, dir string, pw []byte, p restic.Policy) ([]restic.ForgetGroup, error) {
	f.mu.Lock()
	f.seenPW = append(f.seenPW, string(pw))
	f.mu.Unlock()
	return []restic.ForgetGroup{{Host: dir, Keep: make([]restic.Snapshot, p.KeepLast), Remove: make([]restic.Snapshot, 1)}}, nil
}

func (f *fakeRunner) Forget(_ context.Context, _ string, pw []byte, p restic.Policy, log io.Writer) ([]restic.ForgetGroup, error) {
	f.mu.Lock()
	f.seenPW = append(f.seenPW, string(pw))
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(log, "forget %s\n", strings.Join(p.Args(), " "))
	return []restic.ForgetGroup{
		{Keep: make([]restic.Snapshot, 1), Remove: make([]restic.Snapshot, 2)},
		{Keep: make([]restic.Snapshot, 1), Remove: make([]restic.Snapshot, 1)},
	}, nil
}

func (f *fakeRunner) Prune(_ context.Context, _ string, _ []byte, maxUnused string, log io.Writer) error {
	fmt.Fprintf(log, "prune --max-unused %s\n", maxUnused)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, "prune")
	if f.pruneErr != nil {
		return f.pruneErr
	}
	return f.err
}

func (f *fakeRunner) Check(_ context.Context, _ string, _ []byte, subset string, log io.Writer) error {
	fmt.Fprintf(log, "check subset=%q\n", subset)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, "check "+subset)
	return f.err
}

// Unlock echoes the password into the log, to check redaction.
func (f *fakeRunner) Unlock(_ context.Context, _ string, pw []byte, removeAll bool, log io.Writer) (int, error) {
	f.mu.Lock()
	f.seenPW = append(f.seenPW, string(pw))
	f.mu.Unlock()
	fmt.Fprintf(log, "restic says: password was %s\nsuccessfully removed 2 locks\n", pw)
	if removeAll {
		return 5, nil
	}
	return 2, nil
}

func (f *fakeRunner) Snapshots(ctx context.Context, dir string, pw []byte) ([]restic.Snapshot, error) {
	f.mu.Lock()
	f.active++
	f.peak = max(f.peak, f.active)
	f.seenPW = append(f.seenPW, string(pw))
	block, err := f.block, f.err
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
	f.started <- filepath.Base(filepath.Dir(dir)) + "/" + filepath.Base(dir)
	if block {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	t0 := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	return []restic.Snapshot{{ShortID: "a", Time: t0}, {ShortID: "b", Time: t0.Add(24 * time.Hour)}}, nil
}

// fakeStore records jobs in memory.
type fakeStore struct {
	mu        sync.Mutex
	jobs      map[int64]*jobRow
	next      int64
	snapshots map[string]int
	newest    map[string]time.Time
	plans     map[string]store.Plan
	done      chan int64
}

type jobRow struct {
	repo, typ, state, summary, err string
}

func newStore() *fakeStore {
	return &fakeStore{jobs: map[int64]*jobRow{}, snapshots: map[string]int{}, newest: map[string]time.Time{}, plans: map[string]store.Plan{}, done: make(chan int64, 16)}
}

func (s *fakeStore) AddJob(_ context.Context, repo, typ, _ string, _ time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	s.jobs[s.next] = &jobRow{repo: repo, typ: typ, state: StateQueued}
	return s.next, nil
}

func (s *fakeStore) StartJob(_ context.Context, id int64, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[id].state = StateRunning
	return nil
}

func (s *fakeStore) FinishJob(_ context.Context, id int64, state, summary, errText string, _ time.Time) error {
	s.mu.Lock()
	j := s.jobs[id]
	j.state, j.summary, j.err = state, summary, errText
	s.mu.Unlock()
	s.done <- id
	return nil
}

func (s *fakeStore) SetRepoSnapshots(_ context.Context, path string, count int, newest, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots[path], s.newest[path] = count, newest
	return nil
}

func (s *fakeStore) RepoPolicy(_ context.Context, path string) (restic.Policy, bool, error) {
	if path == "bob/main" {
		return restic.Policy{KeepLast: 9}, true, nil
	}
	return restic.DefaultPolicy, false, nil
}

func (s *fakeStore) RepoPlan(_ context.Context, path string) (store.Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plans[path], nil
}

func (s *fakeStore) AdvanceCheckSubset(_ context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.plans[path]
	p.CheckSubsetN = p.CheckSubsetN%p.CheckSubsetT + 1
	s.plans[path] = p
	return nil
}

func (s *fakeStore) job(id int64) jobRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.jobs[id]
}

type env struct {
	m       *Manager
	secrets *fakeSecrets
	runner  *fakeRunner
	store   *fakeStore
	cancel  context.CancelFunc
}

func newEnv(t *testing.T, block bool, maxJobs int) *env {
	t.Helper()
	root := t.TempDir()
	for _, r := range []string{"alice/main", "bob/main", "carol/main"} {
		if err := os.MkdirAll(filepath.Join(root, r), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &env{
		secrets: &fakeSecrets{values: map[string][]byte{
			vault.RepoSecret("alice/main"): []byte("pw-alice"),
			vault.RepoSecret("bob/main"):   []byte("pw-bob"),
			vault.RepoSecret("carol/main"): []byte("pw-carol"),
		}},
		runner: newRunner(block),
		store:  newStore(),
	}
	e.m = New(Options{
		Root: root, Runner: e.runner, Secrets: e.secrets, Store: e.store,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now, MaxJobs: maxJobs,
		LogDir: t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.m.Run(ctx)
	t.Cleanup(func() { cancel(); e.m.Wait() })
	return e
}

func (e *env) waitDone(t *testing.T) int64 {
	t.Helper()
	select {
	case id := <-e.store.done:
		return id
	case <-time.After(10 * time.Second):
		t.Fatal("job did not finish")
		return 0
	}
}

func TestSnapshotsJob(t *testing.T) {
	e := newEnv(t, false, 2)
	id, err := e.m.Submit(context.Background(), "alice/main", Snapshots, Manual)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.waitDone(t); got != id {
		t.Fatalf("finished %d, want %d", got, id)
	}
	j := e.store.job(id)
	if j.state != StateSucceeded || j.summary != "2 snapshots" {
		t.Errorf("job = %+v", j)
	}
	if e.store.snapshots["alice/main"] != 2 || e.store.newest["alice/main"].Day() != 2 {
		t.Errorf("snapshots = %v %v", e.store.snapshots, e.store.newest)
	}
	if e.runner.seenPW[0] != "pw-alice" {
		t.Errorf("runner got %q", e.runner.seenPW[0])
	}
	waitIdle(t, e.m, "alice/main")
	for _, c := range e.secrets.given {
		if string(c) != "\x00\x00\x00\x00\x00\x00\x00\x00" {
			t.Errorf("password copy not zeroed: %q", c)
		}
	}
}

func waitIdle(t *testing.T, m *Manager, repo string) {
	t.Helper()
	for range 1000 {
		if !m.Busy(repo) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s still busy", repo)
}

func TestRefusedWhileSealed(t *testing.T) {
	e := newEnv(t, false, 1)
	e.secrets.seal()
	if _, err := e.m.Submit(context.Background(), "alice/main", Snapshots, Manual); !errors.Is(err, ErrSealed) {
		t.Errorf("err = %v", err)
	}
	if len(e.store.jobs) != 0 {
		t.Error("refused job recorded")
	}
}

func TestSubmitErrors(t *testing.T) {
	e := newEnv(t, true, 1)
	ctx := context.Background()
	if _, err := e.m.Submit(ctx, "dave/main", Snapshots, Manual); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	if _, err := e.m.Submit(ctx, "alice/main", "format-disk", Manual); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown type: %v", err)
	}
	if _, err := e.m.Submit(ctx, "alice/main", Snapshots, Manual); err != nil {
		t.Fatal(err)
	}
	if !e.m.Busy("alice/main") {
		t.Error("not busy")
	}
	if _, err := e.m.Submit(ctx, "alice/main", Snapshots, Manual); !errors.Is(err, ErrBusy) {
		t.Errorf("second job for the same repository: %v", err)
	}
	close(e.runner.release)
	e.waitDone(t)
}

// Sealing while a job runs: the job finishes with the password it already
// has; the next job, queued behind it, is refused because the password is
// fetched only when a job starts.
func TestSealDuringRunningJob(t *testing.T) {
	e := newEnv(t, true, 1)
	ctx := context.Background()
	first, _ := e.m.Submit(ctx, "alice/main", Snapshots, Manual)
	<-e.runner.started
	second, err := e.m.Submit(ctx, "bob/main", Snapshots, Manual)
	if err != nil {
		t.Fatal(err)
	}
	e.secrets.seal()
	close(e.runner.release)
	e.waitDone(t)
	e.waitDone(t)
	if j := e.store.job(first); j.state != StateSucceeded {
		t.Errorf("running job: %+v", j)
	}
	if j := e.store.job(second); j.state != StateRefused || j.err == "" {
		t.Errorf("queued job: %+v", j)
	}
	if len(e.runner.seenPW) != 1 {
		t.Errorf("runner called %d times", len(e.runner.seenPW))
	}
}

// A lock held by someone else (restic gave up after --retry-lock) fails
// the job with restic's message; the repository is free again afterwards.
func TestLockConflict(t *testing.T) {
	e := newEnv(t, false, 1)
	e.runner.err = fmt.Errorf("restic snapshots failed (exit code 11): %w", restic.ErrLocked)
	id, _ := e.m.Submit(context.Background(), "alice/main", Snapshots, Manual)
	e.waitDone(t)
	if j := e.store.job(id); j.state != StateFailed || j.err == "" {
		t.Errorf("job = %+v", j)
	}
	waitIdle(t, e.m, "alice/main")
	e.runner.err = nil
	if _, err := e.m.Submit(context.Background(), "alice/main", Snapshots, Manual); err != nil {
		t.Errorf("retry: %v", err)
	}
	e.waitDone(t)
}

func TestMaxJobs(t *testing.T) {
	e := newEnv(t, true, 2)
	ctx := context.Background()
	for _, r := range []string{"alice/main", "bob/main", "carol/main"} {
		if _, err := e.m.Submit(ctx, r, Snapshots, Manual); err != nil {
			t.Fatal(err)
		}
	}
	<-e.runner.started
	<-e.runner.started
	select {
	case r := <-e.runner.started:
		t.Fatalf("third job %s started while two run", r)
	case <-time.After(100 * time.Millisecond):
	}
	close(e.runner.release)
	for range 3 {
		e.waitDone(t)
	}
	if e.runner.peak != 2 {
		t.Errorf("peak = %d", e.runner.peak)
	}
}

func TestShutdownInterrupts(t *testing.T) {
	e := newEnv(t, true, 1)
	id, _ := e.m.Submit(context.Background(), "alice/main", Snapshots, Manual)
	<-e.runner.started
	e.cancel()
	e.m.Wait()
	if j := e.store.job(id); j.state != StateInterrupted {
		t.Errorf("job = %+v", j)
	}
	for range 100 {
		if _, err := e.m.Submit(context.Background(), "bob/main", Snapshots, Manual); errors.Is(err, ErrStopped) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("Submit after shutdown not refused")
}

func TestUnlockJobLog(t *testing.T) {
	e := newEnv(t, false, 1)
	for typ, want := range map[Type]string{Unlock: "2 locks removed", UnlockAll: "5 locks removed"} {
		id, err := e.m.Submit(context.Background(), "alice/main", typ, Manual)
		if err != nil {
			t.Fatal(err)
		}
		e.waitDone(t)
		waitIdle(t, e.m, "alice/main")
		if j := e.store.job(id); j.state != StateSucceeded || j.summary != want {
			t.Errorf("%s: %+v", typ, j)
		}
		data, err := os.ReadFile(LogPath(e.m.logDir, id))
		if err != nil {
			t.Fatal(err)
		}
		log := string(data)
		if bytes.Contains(data, []byte("pw-alice")) || !strings.Contains(log, "password was [redacted]") ||
			!strings.Contains(log, "succeeded: "+want) || !strings.Contains(log, string(typ)+" alice/main") {
			t.Errorf("%s log:\n%s", typ, log)
		}
	}
}

func TestPreviewForget(t *testing.T) {
	e := newEnv(t, false, 1)
	ctx := context.Background()
	groups, err := e.m.PreviewForget(ctx, "alice/main", restic.Policy{KeepLast: 2})
	if err != nil || len(groups) != 1 || len(groups[0].Keep) != 2 || !strings.HasSuffix(groups[0].Host, "alice/main") {
		t.Fatalf("preview = %+v, %v", groups, err)
	}
	if _, err := e.m.PreviewForget(ctx, "dave/main", restic.DefaultPolicy); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	e.secrets.seal()
	if _, err := e.m.PreviewForget(ctx, "alice/main", restic.DefaultPolicy); !errors.Is(err, ErrSealed) {
		t.Errorf("sealed: %v", err)
	}
	for _, c := range e.secrets.given {
		if strings.Trim(string(c), "\x00") != "" {
			t.Errorf("password copy not zeroed: %q", c)
		}
	}
}

func TestMaintenanceJobs(t *testing.T) {
	e := newEnv(t, false, 1)
	for _, c := range []struct {
		repo    string
		typ     Type
		summary string
		log     string
	}{
		{"bob/main", Forget, "3 snapshots removed, 2 kept", "forget --group-by host,paths --keep-last 9"},
		{"alice/main", Forget, "3 snapshots removed, 2 kept", "--keep-daily 7 --keep-weekly 4"},
		{"alice/main", Prune, "pruned", "prune --max-unused 5%"},
		{"alice/main", Check, "no errors found", "check subset"},
	} {
		id, err := e.m.Submit(context.Background(), c.repo, c.typ, Manual)
		if err != nil {
			t.Fatal(err)
		}
		e.waitDone(t)
		waitIdle(t, e.m, c.repo)
		if j := e.store.job(id); j.state != StateSucceeded || j.summary != c.summary {
			t.Errorf("%s %s: %+v", c.typ, c.repo, j)
		}
		if c.typ == Forget && e.store.snapshots[c.repo] != 2 {
			t.Errorf("forget did not update the snapshot summary: %v", e.store.snapshots)
		}
		data, _ := os.ReadFile(LogPath(e.m.logDir, id))
		if !strings.Contains(string(data), c.log) {
			t.Errorf("%s log lacks %q:\n%s", c.typ, c.log, data)
		}
	}
}

// A forget that cannot get its lock (restic waited --retry-lock and gave
// up) fails; the repository is free for the next attempt.
func TestForgetLockConflict(t *testing.T) {
	e := newEnv(t, false, 1)
	e.runner.err = fmt.Errorf("restic forget failed (exit code 11): %w", restic.ErrLocked)
	id, _ := e.m.Submit(context.Background(), "alice/main", Forget, Manual)
	e.waitDone(t)
	j := e.store.job(id)
	if j.state != StateFailed || !strings.Contains(j.err, "locked") {
		t.Errorf("job = %+v", j)
	}
	waitIdle(t, e.m, "alice/main")
	e.runner.err = nil
	id, _ = e.m.Submit(context.Background(), "alice/main", Forget, Manual)
	e.waitDone(t)
	if j := e.store.job(id); j.state != StateSucceeded {
		t.Errorf("retry: %+v", j)
	}
}

func TestMaintenancePlan(t *testing.T) {
	e := newEnv(t, false, 1)
	e.store.plans["alice/main"] = store.Plan{Unlock: true, Forget: true, Prune: true, Check: true, CheckSubsetT: 3, CheckSubsetN: 3}
	id, err := e.m.Submit(context.Background(), "alice/main", Maintenance, Schedule)
	if err != nil {
		t.Fatal(err)
	}
	e.waitDone(t)
	waitIdle(t, e.m, "alice/main")
	j := e.store.job(id)
	want := "unlock: 2 locks removed; forget: 3 snapshots removed, 2 kept; prune: pruned; check: no errors found (data subset 3/3)"
	if j.state != StateSucceeded || j.summary != want {
		t.Errorf("job = %+v", j)
	}
	if n := e.store.plans["alice/main"].CheckSubsetN; n != 1 {
		t.Errorf("subset after 3/3 = %d, want 1", n)
	}

	// A failed step stops the plan: no check, no advance.
	e.runner.pruneErr = errors.New("disk full")
	e.runner.steps = nil
	id, _ = e.m.Submit(context.Background(), "alice/main", Maintenance, Schedule)
	e.waitDone(t)
	waitIdle(t, e.m, "alice/main")
	j = e.store.job(id)
	if j.state != StateFailed || !strings.Contains(j.err, "step prune: disk full") || !strings.Contains(j.err, "done before: unlock") {
		t.Errorf("job = %+v", j)
	}
	if fmt.Sprint(e.runner.steps) != "[prune]" || e.store.plans["alice/main"].CheckSubsetN != 1 {
		t.Errorf("steps %v, subset %d", e.runner.steps, e.store.plans["alice/main"].CheckSubsetN)
	}

	// Only check, without data subset.
	e.runner.pruneErr = nil
	e.runner.steps = nil
	e.store.plans["alice/main"] = store.Plan{Check: true}
	id, _ = e.m.Submit(context.Background(), "alice/main", Maintenance, Schedule)
	e.waitDone(t)
	if j := e.store.job(id); j.summary != "check: no errors found" || fmt.Sprint(e.runner.steps) != "[check ]" {
		t.Errorf("job = %+v, steps %v", j, e.runner.steps)
	}
}
