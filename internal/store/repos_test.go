package store

import (
	"context"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
)

func TestRepos(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return t0 }
	if err := s.SyncRepos(ctx, []string{"a/one", "b/two"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRepoUsage(ctx, "a/one", repos.Usage{Bytes: 100, Files: 3}, t0); err != nil {
		t.Fatal(err)
	}

	t1 := t0.Add(time.Hour)
	s.now = func() time.Time { return t1 }
	if err := s.SyncRepos(ctx, []string{"a/one", "c/three"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRepos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d repos: %+v", len(got), got)
	}
	a, b, c := got[0], got[1], got[2]
	if a.Path != "a/one" || a.Missing || !a.FirstSeen.Equal(t0) || !a.LastSeen.Equal(t1) {
		t.Errorf("a: %+v", a)
	}
	if a.Usage == nil || *a.Usage != (repos.Usage{Bytes: 100, Files: 3}) || !a.UsageTime.Equal(t0) {
		t.Errorf("a usage: %+v at %v", a.Usage, a.UsageTime)
	}
	if b.Path != "b/two" || !b.Missing || !b.LastSeen.Equal(t0) {
		t.Errorf("b: %+v", b)
	}
	if c.Path != "c/three" || c.Missing || c.Usage != nil {
		t.Errorf("c: %+v", c)
	}

	// A repository that comes back is present again.
	if err := s.SyncRepos(ctx, []string{"b/two"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListRepos(ctx)
	if got[1].Missing || !got[0].Missing {
		t.Errorf("after return: %+v", got)
	}
}
