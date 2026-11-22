package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPlan(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	_ = s.SyncRepos(ctx, []string{"a/one", "b/two", "c/gone"})
	_ = s.SyncRepos(ctx, []string{"a/one", "b/two"})

	p, err := s.RepoPlan(ctx, "a/one")
	if err != nil || p.Enabled || !p.Unlock || !p.Forget || !p.Prune || !p.Check || p.CheckSubsetT != 7 || p.CheckSubsetN != 1 {
		t.Fatalf("defaults: %+v %v", p, err)
	}
	want := Plan{Enabled: true, Schedule: "30 3 * * 0", Forget: true, Prune: true, Check: true, CheckSubsetT: 3}
	for _, path := range []string{"a/one", "c/gone"} {
		if err := s.SetRepoPlan(ctx, path, want); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.RepoPlan(ctx, "a/one")
	want.CheckSubsetN = 1
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	for _, n := range []int{2, 3, 1, 2} {
		_ = s.AdvanceCheckSubset(ctx, "a/one")
		if got, _ := s.RepoPlan(ctx, "a/one"); got.CheckSubsetN != n {
			t.Errorf("after advance: n = %d, want %d", got.CheckSubsetN, n)
		}
	}
	// Shrinking T moves n back into range.
	want.CheckSubsetT = 1
	_ = s.SetRepoPlan(ctx, "a/one", want)
	if got, _ := s.RepoPlan(ctx, "a/one"); got.CheckSubsetN != 1 {
		t.Errorf("n = %d after shrinking", got.CheckSubsetN)
	}
	if err := s.SetRepoPlan(ctx, "a/one", Plan{CheckSubsetT: MaxCheckSubsetT + 1}); err == nil {
		t.Error("too large T accepted")
	}
	if err := s.SetRepoPlan(ctx, "x/y", want); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}

	list, err := s.ScheduledRepos(ctx)
	if err != nil || len(list) != 1 || list[0].Path != "a/one" || list[0].Plan.Schedule != "30 3 * * 0" {
		t.Errorf("scheduled (missing repositories excluded): %+v %v", list, err)
	}

	if err := s.AddSkippedJob(ctx, "a/one", "maintenance", "schedule", "the vault is sealed", time.Now()); err != nil {
		t.Fatal(err)
	}
	jobs, _ := s.ListJobs(ctx, 1, 0)
	if jobs[0].State != "skipped" || jobs[0].Error != "the vault is sealed" || jobs[0].Trigger != "schedule" {
		t.Errorf("skipped job: %+v", jobs[0])
	}
	// Interrupting at startup leaves skipped jobs alone.
	if n, _ := s.InterruptJobs(ctx, time.Now()); n != 0 {
		t.Errorf("interrupted %d", n)
	}
}
