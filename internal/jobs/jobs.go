// Package jobs runs restic jobs against repositories (see "Maintenance
// jobs" in docs/architecture.md): at most one job per repository, at most
// MaxJobs at a time, only while the vault is unsealed.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// Type is a job type.
type Type string

// Job types.
const (
	Snapshots Type = "snapshots"  // refresh the cached snapshot summary
	Unlock    Type = "unlock"     // remove stale locks
	UnlockAll Type = "unlock-all" // remove all locks, also of running backups
	Forget    Type = "forget"     // remove snapshots per the repository's policy
	Prune     Type = "prune"      // remove unreferenced data
	Check     Type = "check"      // verify the repository structure
	// Maintenance runs the steps of the repository's plan (unlock,
	// forget, prune, check) as one job.
	Maintenance Type = "maintenance"
)

// Valid reports whether t is a known job type.
func (t Type) Valid() bool {
	switch t {
	case Snapshots, Unlock, UnlockAll, Forget, Prune, Check, Maintenance:
		return true
	}
	return false
}

// Trigger says who started a job.
type Trigger string

// Triggers.
const (
	Manual   Trigger = "manual"
	Schedule Trigger = "schedule"
)

// Job states as stored in the database.
const (
	StateQueued      = "queued"
	StateRunning     = "running"
	StateSucceeded   = "succeeded"
	StateFailed      = "failed"
	StateRefused     = "refused"     // sealed (or password gone) when it was its turn
	StateInterrupted = "interrupted" // shutdown or restart
)

// Errors returned by Submit.
var (
	ErrSealed     = errors.New("the vault is sealed")
	ErrNoPassword = errors.New("no password stored for this repository")
	ErrBusy       = errors.New("a job for this repository is already queued or running")
	ErrQueueFull  = errors.New("too many queued jobs")
	ErrStopped    = errors.New("job manager is not running")
	ErrUnknown    = errors.New("unknown job type")
)

// queueSize bounds the jobs waiting for a free slot.
const queueSize = 256

// Secrets is the part of the vault jobs need.
type Secrets interface {
	Sealed() bool
	Has(name string) bool
	// Secret returns a copy that the caller zeroes.
	Secret(name string) ([]byte, error)
}

// Store records jobs and their results (implemented by *store.Store).
type Store interface {
	AddJob(ctx context.Context, repo, typ, trigger string, queued time.Time) (int64, error)
	StartJob(ctx context.Context, id int64, at time.Time) error
	FinishJob(ctx context.Context, id int64, state, summary, errText string, at time.Time) error
	SetRepoSnapshots(ctx context.Context, path string, count int, newest, at time.Time) error
	RepoPolicy(ctx context.Context, path string) (restic.Policy, bool, error)
	RepoPlan(ctx context.Context, path string) (store.Plan, error)
	AdvanceCheckSubset(ctx context.Context, path string) error
}

// Manager queues and runs jobs. Create it with New, then call Run once.
type Manager struct {
	root    string
	runner  restic.Runner
	secrets Secrets
	store   Store
	logger  *slog.Logger
	now     func() time.Time
	workers int
	logDir  string

	queue chan task
	wg    sync.WaitGroup

	mu      sync.Mutex
	busy    map[string]int64 // repository -> queued or running job id
	running bool
}

type task struct {
	id   int64
	repo string
	typ  Type
}

// Options configure a Manager.
type Options struct {
	// Root is the repository root (BELAYPOINT_REPOS_DIR).
	Root    string
	Runner  restic.Runner
	Secrets Secrets
	Store   Store
	Logger  *slog.Logger
	Now     func() time.Time
	// MaxJobs is the number of jobs that run at the same time.
	MaxJobs int
	// LogDir receives one log file per job (<id>.log).
	LogDir string
}

// New returns a Manager; jobs run only after Run was called.
func New(o Options) *Manager {
	return &Manager{
		root: o.Root, runner: o.Runner, secrets: o.Secrets, store: o.Store, logger: o.Logger,
		now: o.Now, workers: max(o.MaxJobs, 1), logDir: o.LogDir,
		queue: make(chan task, queueSize),
		busy:  map[string]int64{},
	}
}

// Run starts the workers. They stop when ctx is cancelled: a running
// restic gets SIGINT; queued jobs stay "queued" in the database and are
// marked interrupted at the next start. Wait waits for them.
//
// Each worker is a goroutine that takes tasks from a channel, like
// several consumers of a BlockingCollection<T> in C#.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.running = true
	m.mu.Unlock()
	for range m.workers {
		m.wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-m.queue:
					m.run(ctx, t)
				}
			}
		})
	}
	m.wg.Go(func() {
		<-ctx.Done()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	})
}

// Wait blocks until all workers have stopped.
func (m *Manager) Wait() { m.wg.Wait() }

// Busy reports whether a job for repo is queued or running.
func (m *Manager) Busy(repo string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.busy[repo]
	return ok
}

// Submit queues a job. The caller has checked that repo is a discovered,
// present repository. Jobs are refused while sealed and for repositories
// without a stored password.
func (m *Manager) Submit(ctx context.Context, repo string, typ Type, trigger Trigger) (int64, error) {
	if !typ.Valid() {
		return 0, fmt.Errorf("%w: %q", ErrUnknown, typ)
	}
	if m.secrets.Sealed() {
		return 0, ErrSealed
	}
	if !m.secrets.Has(vault.RepoSecret(repo)) {
		return 0, ErrNoPassword
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return 0, ErrStopped
	}
	if _, ok := m.busy[repo]; ok {
		return 0, ErrBusy
	}
	if len(m.queue) == cap(m.queue) {
		return 0, ErrQueueFull
	}
	id, err := m.store.AddJob(ctx, repo, string(typ), string(trigger), m.now())
	if err != nil {
		return 0, err
	}
	m.busy[repo] = id
	// Cannot block: the length was checked under m.mu, and only Submit
	// sends.
	m.queue <- task{id: id, repo: repo, typ: typ}
	return id, nil
}

// PreviewForget shows what forget with the policy would remove. It runs
// right away, outside the queue: it is read-only and takes no lock
// (--no-lock), so it cannot conflict with jobs or backups.
func (m *Manager) PreviewForget(ctx context.Context, repo string, p restic.Policy) ([]restic.ForgetGroup, error) {
	if m.secrets.Sealed() {
		return nil, ErrSealed
	}
	pw, err := m.secrets.Secret(vault.RepoSecret(repo))
	if errors.Is(err, vault.ErrNotFound) {
		return nil, ErrNoPassword
	}
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	dir, err := repos.Dir(m.root, repo)
	if err != nil {
		return nil, err
	}
	return m.runner.ForgetPreview(ctx, dir, pw, p)
}

// run executes one job. The password is fetched only now, so a job that
// waited in the queue while the vault was sealed is refused.
func (m *Manager) run(ctx context.Context, t task) {
	defer func() {
		m.mu.Lock()
		delete(m.busy, t.repo)
		m.mu.Unlock()
	}()
	// Results are recorded even when ctx is cancelled (shutdown); the
	// store is closed only after Wait.
	record := context.WithoutCancel(ctx)
	log := m.logger.With("job", t.id, "type", t.typ, "repo", t.repo)
	finish := func(state, summary string, err error) {
		var errText string
		if err != nil {
			errText = err.Error()
			log.Warn("job "+state, "err", err)
		} else {
			log.Info("job "+state, "summary", summary)
		}
		if err := m.store.FinishJob(record, t.id, state, summary, errText, m.now()); err != nil {
			log.Error("recording job result", "err", err)
		}
	}

	pw, err := m.secrets.Secret(vault.RepoSecret(t.repo))
	if err != nil {
		finish(StateRefused, "", err)
		return
	}
	defer clear(pw)
	dir, err := repos.Dir(m.root, t.repo)
	if err != nil {
		finish(StateFailed, "", err)
		return
	}
	jl, err := createLog(m.logDir, t.id, pw)
	if err != nil {
		finish(StateFailed, "", err)
		return
	}
	// Deferred calls run last-in, first-out (like nested using blocks in
	// C#): the log is closed before the password is zeroed.
	defer func() {
		if err := jl.Close(); err != nil {
			log.Warn("closing job log", "err", err)
		}
	}()
	if err := m.store.StartJob(record, t.id, m.now()); err != nil {
		log.Error("recording job start", "err", err)
	}
	log.Info("job started")
	jl.Printf(m.now(), "job %d: %s %s (%s)", t.id, t.typ, t.repo, "started")

	summary, err := m.execute(ctx, record, t, dir, pw, jl)
	switch {
	case err == nil:
		jl.Printf(m.now(), "succeeded: %s", summary)
		finish(StateSucceeded, summary, nil)
	case ctx.Err() != nil:
		jl.Printf(m.now(), "interrupted: %v", err)
		finish(StateInterrupted, "", err)
	default:
		jl.Printf(m.now(), "failed: %v", err)
		finish(StateFailed, "", err)
	}
}

// storeSnapshots caches count and newest time of a snapshot list.
func (m *Manager) storeSnapshots(ctx context.Context, repo string, list []restic.Snapshot) error {
	var newest time.Time
	for _, s := range list {
		if s.Time.After(newest) {
			newest = s.Time
		}
	}
	return m.store.SetRepoSnapshots(ctx, repo, len(list), newest, m.now())
}

func (m *Manager) execute(ctx, record context.Context, t task, dir string, pw []byte, jl *jobLog) (string, error) {
	switch t.typ {
	case Snapshots:
		list, err := m.runner.Snapshots(ctx, dir, pw)
		if err != nil {
			return "", err
		}
		if err := m.storeSnapshots(record, t.repo, list); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d snapshots", len(list)), nil
	case Unlock, UnlockAll:
		return m.unlock(ctx, dir, pw, t.typ == UnlockAll, jl)
	case Forget:
		return m.forget(ctx, record, t.repo, dir, pw, jl)
	case Prune:
		return m.prune(ctx, dir, pw, jl)
	case Check:
		return m.check(ctx, dir, pw, "", jl)
	case Maintenance:
		return m.maintenance(ctx, record, t.repo, dir, pw, jl)
	}
	return "", fmt.Errorf("%w: %q", ErrUnknown, t.typ)
}

func (m *Manager) unlock(ctx context.Context, dir string, pw []byte, all bool, jl *jobLog) (string, error) {
	n, err := m.runner.Unlock(ctx, dir, pw, all, jl)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d locks removed", n), nil
}

func (m *Manager) forget(ctx, record context.Context, repo, dir string, pw []byte, jl *jobLog) (string, error) {
	p, _, err := m.store.RepoPolicy(record, repo)
	if err != nil {
		return "", err
	}
	jl.Printf(m.now(), "policy: %s", strings.Join(p.Args(), " "))
	groups, err := m.runner.Forget(ctx, dir, pw, p, jl)
	if err != nil {
		return "", err
	}
	// The kept snapshots are all that is left: update the cached summary
	// without another listing.
	var kept []restic.Snapshot
	removed := 0
	for _, g := range groups {
		kept = append(kept, g.Keep...)
		removed += len(g.Remove)
	}
	if err := m.storeSnapshots(record, repo, kept); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d snapshots removed, %d kept", removed, len(kept)), nil
}

func (m *Manager) prune(ctx context.Context, dir string, pw []byte, jl *jobLog) (string, error) {
	if err := m.runner.Prune(ctx, dir, pw, restic.DefaultMaxUnused, jl); err != nil {
		return "", err
	}
	return "pruned", nil
}

func (m *Manager) check(ctx context.Context, dir string, pw []byte, subset string, jl *jobLog) (string, error) {
	if err := m.runner.Check(ctx, dir, pw, subset, jl); err != nil {
		return "", err
	}
	if subset != "" {
		return "no errors found (data subset " + subset + ")", nil
	}
	return "no errors found", nil
}

// maintenance runs the steps of the repository's plan in order; a failed
// step stops the plan. check reads the next data subset of the rotation,
// which advances only when the check succeeded.
func (m *Manager) maintenance(ctx, record context.Context, repo, dir string, pw []byte, jl *jobLog) (string, error) {
	p, err := m.store.RepoPlan(record, repo)
	if err != nil {
		return "", err
	}
	var done []string
	step := func(name string, run func() (string, error)) error {
		jl.Printf(m.now(), "step %s", name)
		summary, err := run()
		if err != nil {
			return fmt.Errorf("step %s: %w", name, err)
		}
		done = append(done, name+": "+summary)
		return nil
	}
	steps := []struct {
		on   bool
		name string
		run  func() (string, error)
	}{
		{p.Unlock, "unlock", func() (string, error) { return m.unlock(ctx, dir, pw, false, jl) }},
		{p.Forget, "forget", func() (string, error) { return m.forget(ctx, record, repo, dir, pw, jl) }},
		{p.Prune, "prune", func() (string, error) { return m.prune(ctx, dir, pw, jl) }},
		{p.Check, "check", func() (string, error) {
			subset := ""
			if p.CheckSubsetT > 0 {
				subset = fmt.Sprintf("%d/%d", p.CheckSubsetN, p.CheckSubsetT)
			}
			summary, err := m.check(ctx, dir, pw, subset, jl)
			if err == nil && subset != "" {
				err = m.store.AdvanceCheckSubset(record, repo)
			}
			return summary, err
		}},
	}
	for _, s := range steps {
		if !s.on {
			continue
		}
		if err := step(s.name, s.run); err != nil {
			if len(done) > 0 {
				err = fmt.Errorf("%w (done before: %s)", err, strings.Join(done, "; "))
			}
			return "", err
		}
	}
	if len(done) == 0 {
		return "no steps enabled", nil
	}
	return strings.Join(done, "; "), nil
}
