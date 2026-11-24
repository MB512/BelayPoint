package store

import (
	"context"
	"errors"
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

func TestRepoArchived(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	_ = s.SyncRepos(ctx, []string{"a/one", "b/two"})
	if got, err := s.RepoArchived(ctx, "a/one"); err != nil || got {
		t.Fatalf("new repository archived=%v, %v", got, err)
	}
	if err := s.SetRepoArchived(ctx, "a/one", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.RepoArchived(ctx, "a/one"); !got {
		t.Error("flag not stored")
	}
	list, _ := s.ListRepos(ctx)
	if !list[0].Archived || list[1].Archived {
		t.Errorf("list: %+v", list)
	}
	// The flag survives a rediscovery (also of a repository that was missing).
	_ = s.SyncRepos(ctx, []string{"b/two"})
	_ = s.SyncRepos(ctx, []string{"a/one", "b/two"})
	if got, _ := s.RepoArchived(ctx, "a/one"); !got {
		t.Error("flag lost after rediscovery")
	}
	_ = s.SetRepoArchived(ctx, "a/one", false)
	if got, _ := s.RepoArchived(ctx, "a/one"); got {
		t.Error("flag not cleared")
	}
	for _, f := range []func() error{
		func() error { _, err := s.RepoArchived(ctx, "x/y"); return err },
		func() error { return s.SetRepoArchived(ctx, "x/y", true) },
	} {
		if err := f(); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown repository: %v", err)
		}
	}
}
