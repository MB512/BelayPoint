package store

import (
	"context"
	"errors"
	"testing"

	"github.com/MB512/belaypoint/internal/restic"
)

func TestRepoPolicy(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	_ = s.SyncRepos(ctx, []string{"a/one"})
	p, custom, err := s.RepoPolicy(ctx, "a/one")
	if err != nil || custom || p != restic.DefaultPolicy {
		t.Fatalf("default: %+v %v %v", p, custom, err)
	}
	want := restic.Policy{KeepLast: 3, KeepWithin: "30d"}
	if err := s.SetRepoPolicy(ctx, "a/one", &want); err != nil {
		t.Fatal(err)
	}
	if p, custom, _ := s.RepoPolicy(ctx, "a/one"); !custom || p != want {
		t.Errorf("custom: %+v %v", p, custom)
	}
	if err := s.SetRepoPolicy(ctx, "a/one", &restic.Policy{}); !errors.Is(err, restic.ErrPolicy) {
		t.Errorf("empty policy: %v", err)
	}
	if err := s.SetRepoPolicy(ctx, "a/one", nil); err != nil {
		t.Fatal(err)
	}
	if _, custom, _ := s.RepoPolicy(ctx, "a/one"); custom {
		t.Error("reset did not apply")
	}
	if err := s.SetRepoPolicy(ctx, "x/y", &want); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown repository: %v", err)
	}
	if _, _, err := s.RepoPolicy(ctx, "x/y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown repository: %v", err)
	}
}
