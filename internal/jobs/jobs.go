// Package jobs runs restic jobs against repositories (see "Maintenance
// jobs" in docs/architecture.md): at most one job per repository, at most
// MaxJobs at a time, only while the vault is unsealed.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/vault"
)

// Type is a job type.
type Type string

// Job types.
const (
	Snapshots Type = "snapshots" // refresh the cached snapshot summary
)

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
}

// New returns a Manager; jobs run only after Run was called.
func New(o Options) *Manager {
	return &Manager{
		root: o.Root, runner: o.Runner, secrets: o.Secrets, store: o.Store, logger: o.Logger,
		now: o.Now, workers: max(o.MaxJobs, 1),
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
	if typ != Snapshots {
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
	if err := m.store.StartJob(record, t.id, m.now()); err != nil {
		log.Error("recording job start", "err", err)
	}
	log.Info("job started")

	summary, err := m.execute(ctx, record, t, dir, pw)
	switch {
	case err == nil:
		finish(StateSucceeded, summary, nil)
	case ctx.Err() != nil:
		finish(StateInterrupted, "", err)
	default:
		finish(StateFailed, "", err)
	}
}

func (m *Manager) execute(ctx, record context.Context, t task, dir string, pw []byte) (string, error) {
	switch t.typ {
	case Snapshots:
		list, err := m.runner.Snapshots(ctx, dir, pw)
		if err != nil {
			return "", err
		}
		var newest time.Time
		for _, s := range list {
			if s.Time.After(newest) {
				newest = s.Time
			}
		}
		if err := m.store.SetRepoSnapshots(record, t.repo, len(list), newest, m.now()); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d snapshots", len(list)), nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknown, t.typ)
}
