package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/store"
)

func TestValidate(t *testing.T) {
	for _, ok := range []string{"30 3 * * 0", "0 2 * * *", "@daily", "@weekly", "15 4 1 * *", "0 1,13 * * *"} {
		if err := Validate(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "* * * * *", "*/30 * * * *", "@every 2h", "0 3 * *", "TZ=UTC 0 3 * * *", "0 3 * * * *", "nonsense"} {
		if err := Validate(bad); !errors.Is(err, ErrSchedule) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

type fakeStore struct {
	mu      sync.Mutex
	repos   []store.ScheduledRepo
	skipped []string
}

func (f *fakeStore) ScheduledRepos(context.Context) ([]store.ScheduledRepo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.repos, nil
}

func (f *fakeStore) AddSkippedJob(_ context.Context, repo, typ, trigger, reason string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.skipped = append(f.skipped, repo+" "+typ+" "+trigger+" "+reason)
	return nil
}

type fakeJobs struct {
	mu        sync.Mutex
	err       error
	submitted []string
}

func (f *fakeJobs) Submit(_ context.Context, repo string, typ jobs.Type, trigger jobs.Trigger) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.submitted = append(f.submitted, repo+" "+string(typ)+" "+string(trigger))
	return 1, nil
}

func newTest(t *testing.T) (*Scheduler, *fakeStore, *fakeJobs, *[]string) {
	t.Helper()
	st, j := &fakeStore{}, &fakeJobs{}
	var notified []string
	loc, _ := time.LoadLocation("Europe/Berlin")
	s := New(st, j, slog.New(slog.NewTextHandler(io.Discard, nil)), loc, time.Now, func(repo, reason string) {
		notified = append(notified, repo+": "+reason)
	})
	return s, st, j, &notified
}

func TestReloadAndNext(t *testing.T) {
	s, st, _, _ := newTest(t)
	st.repos = []store.ScheduledRepo{
		{Path: "alice/main", Plan: store.Plan{Enabled: true, Schedule: "30 3 * * *"}},
		{Path: "bob/main", Plan: store.Plan{Enabled: true, Schedule: "* * * * *"}}, // invalid: too often
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	next := s.Next("alice/main")
	if next.IsZero() || next.In(next.Location()).Hour() != 3 || next.Minute() != 30 || next.Location().String() != "Europe/Berlin" {
		t.Errorf("next = %v", next)
	}
	if !s.Next("bob/main").IsZero() {
		t.Error("invalid schedule was added")
	}
	st.repos = st.repos[1:]
	if err := s.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Next("alice/main").IsZero() {
		t.Error("removed plan still scheduled")
	}
}

func TestFire(t *testing.T) {
	s, st, j, notified := newTest(t)
	s.fire("alice/main")
	if len(j.submitted) != 1 || j.submitted[0] != "alice/main maintenance schedule" || len(st.skipped) != 0 {
		t.Errorf("submitted %v, skipped %v", j.submitted, st.skipped)
	}
	// Sealed: recorded as skipped and reported.
	j.err = jobs.ErrSealed
	s.fire("alice/main")
	if len(st.skipped) != 1 || st.skipped[0] != "alice/main maintenance schedule the vault is sealed" {
		t.Errorf("skipped %v", st.skipped)
	}
	if len(*notified) != 1 {
		t.Errorf("notified %v", *notified)
	}
}
