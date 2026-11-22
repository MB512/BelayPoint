// Package scheduler starts the maintenance plan of each repository at the
// times of its cron schedule (see "Maintenance plan" in
// docs/architecture.md). A run that cannot start (vault sealed, no
// password, a job still running) is recorded as skipped.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/store"
)

// MinInterval is the shortest time allowed between two runs of a plan.
const MinInterval = time.Hour

// ErrSchedule is returned by Validate.
var ErrSchedule = errors.New("invalid schedule")

// parser accepts standard 5-field expressions ("30 3 * * 0") and the
// descriptors @daily, @weekly, @monthly; @every is refused below.
var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Validate checks a cron expression and that its runs are at least
// MinInterval apart.
func Validate(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("%w: empty", ErrSchedule)
	}
	if strings.HasPrefix(expr, "@every") || strings.HasPrefix(expr, "TZ=") || strings.HasPrefix(expr, "CRON_TZ=") {
		return fmt.Errorf("%w: use a cron expression such as \"30 3 * * 0\" or @daily, @weekly", ErrSchedule)
	}
	sched, err := parser.Parse(expr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSchedule, err) //nolint:errorlint // the parser's message is enough
	}
	t := sched.Next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	for range 500 {
		next := sched.Next(t)
		if next.Sub(t) < MinInterval {
			return fmt.Errorf("%w: runs must be at least %v apart", ErrSchedule, MinInterval)
		}
		t = next
	}
	return nil
}

// Store is what the scheduler reads and records (implemented by
// *store.Store).
type Store interface {
	ScheduledRepos(ctx context.Context) ([]store.ScheduledRepo, error)
	AddSkippedJob(ctx context.Context, repo, typ, trigger, reason string, at time.Time) error
}

// Jobs queues the plan job (implemented by *jobs.Manager).
type Jobs interface {
	Submit(ctx context.Context, repo string, typ jobs.Type, trigger jobs.Trigger) (int64, error)
}

// Skipped is told about every skipped run (notifications); may be nil.
type Skipped func(repo, reason string)

// Scheduler holds one cron entry per repository with an enabled plan.
type Scheduler struct {
	store   Store
	jobs    Jobs
	logger  *slog.Logger
	now     func() time.Time
	skipped Skipped

	mu      sync.Mutex
	cron    *cron.Cron
	entries map[string]cron.EntryID
}

// New returns a Scheduler for the time zone loc; call Start.
func New(st Store, j Jobs, logger *slog.Logger, loc *time.Location, now func() time.Time, skipped Skipped) *Scheduler {
	return &Scheduler{
		store: st, jobs: j, logger: logger, now: now, skipped: skipped,
		cron:    cron.New(cron.WithParser(parser), cron.WithLocation(loc)),
		entries: map[string]cron.EntryID{},
	}
}

// Start loads the plans and runs the schedule until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) error {
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.cron.Start()
	go func() {
		<-ctx.Done()
		<-s.cron.Stop().Done() // waits for a fire() that is just running
	}()
	return nil
}

// Reload replaces all entries with the plans in the store; call it after a
// plan changed or repositories were rediscovered.
func (s *Scheduler) Reload(ctx context.Context) error {
	list, err := s.store.ScheduledRepos(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.entries {
		s.cron.Remove(id)
	}
	clear(s.entries)
	for _, r := range list {
		if err := Validate(r.Plan.Schedule); err != nil {
			s.logger.Warn("maintenance plan not scheduled", "repo", r.Path, "err", err)
			continue
		}
		repo := r.Path
		id, err := s.cron.AddFunc(r.Plan.Schedule, func() { s.fire(repo) })
		if err != nil {
			s.logger.Warn("maintenance plan not scheduled", "repo", repo, "err", err)
			continue
		}
		s.entries[repo] = id
	}
	s.logger.Info("maintenance plans scheduled", "repositories", len(s.entries))
	return nil
}

// Next returns the next run of the repository's plan (zero if none).
func (s *Scheduler) Next(repo string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.entries[repo]
	if !ok {
		return time.Time{}
	}
	return s.cron.Entry(id).Next
}

// fire queues the plan job; if that is refused, the run is recorded as
// skipped.
func (s *Scheduler) fire(repo string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := s.jobs.Submit(ctx, repo, jobs.Maintenance, jobs.Schedule)
	if err == nil {
		s.logger.Info("scheduled maintenance queued", "repo", repo, "job", id)
		return
	}
	s.logger.Warn("scheduled maintenance skipped", "repo", repo, "reason", err)
	if err := s.store.AddSkippedJob(ctx, repo, string(jobs.Maintenance), string(jobs.Schedule), err.Error(), s.now()); err != nil {
		s.logger.Error("recording skipped run", "repo", repo, "err", err)
	}
	if s.skipped != nil {
		s.skipped(repo, err.Error())
	}
}
