package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestJobs(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := s.AddJob(ctx, "alice/main", "snapshots", "manual", t0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.AddJob(ctx, "bob/main", "snapshots", "manual", t0)
	c, _ := s.AddJob(ctx, "carol/main", "snapshots", "manual", t0)
	if err := s.StartJob(ctx, a, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishJob(ctx, a, "succeeded", "3 snapshots", "", t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = s.StartJob(ctx, b, t0.Add(time.Second))

	n, err := s.InterruptJobs(ctx, t0.Add(time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("interrupted %d, %v", n, err)
	}
	list, err := s.ListJobs(ctx, 10, 0)
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %v %v", list, err)
	}
	if list[0].ID != c || list[0].State != "interrupted" || !list[0].Started.IsZero() {
		t.Errorf("c: %+v", list[0])
	}
	if list[1].State != "interrupted" || list[1].Started.IsZero() {
		t.Errorf("b: %+v", list[1])
	}
	j := list[2]
	if j.ID != a || j.State != "succeeded" || j.Summary != "3 snapshots" || !j.Finished.Equal(t0.Add(2*time.Second)) || j.Repo != "alice/main" {
		t.Errorf("a: %+v", j)
	}
	if page, _ := s.ListJobs(ctx, 10, b); len(page) != 1 || page[0].ID != a {
		t.Errorf("page: %+v", page)
	}
	if one, err := s.Job(ctx, a); err != nil || one != j {
		t.Errorf("Job(%d) = %+v, %v; want %+v", a, one, err, j)
	}
	if _, err := s.Job(ctx, c+100); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown job: %v", err)
	}
}

func TestRepoSnapshots(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	_ = s.SyncRepos(ctx, []string{"a/one", "b/two"})
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.SetRepoSnapshots(ctx, "a/one", 5, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_ = s.SetRepoSnapshots(ctx, "b/two", 0, time.Time{}, t0)
	list, _ := s.ListRepos(ctx)
	a, b := list[0].Snapshots, list[1].Snapshots
	if a == nil || a.Count != 5 || !a.Newest.Equal(t0) || !a.Time.Equal(t0.Add(time.Hour)) {
		t.Errorf("a: %+v", a)
	}
	if b == nil || b.Count != 0 || !b.Newest.IsZero() {
		t.Errorf("b: %+v", b)
	}
}
