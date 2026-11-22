package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/vault"
)

func TestRefreshSnapshots(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	for _, r := range []string{"alice/main", "bob/main", "carol/main"} {
		makeRepo(t, e.reposDir, r)
	}
	_ = e.store.SyncRepos(ctx, []string{"alice/main", "bob/main", "carol/main", "gone/repo"})
	_ = e.store.SyncRepos(ctx, []string{"alice/main", "bob/main", "carol/main"})
	e.vault.secrets = []string{vault.RepoSecret("alice/main"), vault.RepoSecret("bob/main"), vault.RepoSecret("gone/repo")}
	e.jobs.busy["bob/main"] = true
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	if w := post(e.h, "/repos/snapshots", cookie, url.Values{"repo": {"alice/main"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("without CSRF: %d", w.Code)
	}
	if w := post(e.h, "/repos/snapshots", cookie, url.Values{"csrf_token": {csrf}, "repo": {"gone/repo"}}, nil); w.Code != http.StatusNotFound {
		t.Errorf("missing repository: %d", w.Code)
	}
	wantRedirect(t, post(e.h, "/repos/snapshots", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}}, nil), "/")
	if !slices.Equal(e.jobs.submitted, []string{"snapshots alice/main"}) || !e.audit.has("job submitted") {
		t.Errorf("submitted %v", e.jobs.submitted)
	}

	// All: only present repositories with a password and no running job.
	e.jobs.submitted = nil
	wantRedirect(t, post(e.h, "/repos/snapshots", cookie, url.Values{"csrf_token": {csrf}}, nil), "/")
	if !slices.Equal(e.jobs.submitted, []string{"snapshots alice/main"}) {
		t.Errorf("submitted %v", e.jobs.submitted)
	}

	// Errors are shown on the overview.
	e.jobs.err = jobs.ErrSealed
	w := post(e.h, "/repos/snapshots", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}}, nil)
	if w.Code != http.StatusServiceUnavailable || strings.Count(w.Body.String(), "the vault is sealed") != 1 {
		t.Errorf("error: %d", w.Code)
	}

	body := getWithCookie(e.h, "/", cookie).Body.String()
	if !strings.Contains(body, "job running") || !strings.Contains(body, "Refresh snapshots") {
		t.Error("overview lacks the busy badge or the refresh button")
	}
}

func TestOverviewSnapshots(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	_ = e.store.SetRepoSnapshots(ctx, "alice/main", 17, time.Now().Add(-5*time.Hour), time.Now())
	cookie := login(t, e)
	if body := getWithCookie(e.h, "/", cookie).Body.String(); !strings.Contains(body, "17, newest 5 h ago") {
		t.Error("overview lacks the snapshot summary")
	}
}

func TestJobsPage(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	t0 := time.Now()
	id, _ := e.store.AddJob(ctx, "alice/main", "snapshots", "manual", t0)
	_ = e.store.StartJob(ctx, id, t0)
	_ = e.store.FinishJob(ctx, id, "failed", "", "restic snapshots failed: <locked>", t0.Add(3*time.Second))
	cookie := login(t, e)
	w := getWithCookie(e.h, "/jobs", cookie)
	body := w.Body.String()
	for _, want := range []string{"alice/main", "snapshots", "failed", "3s", "&lt;locked&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("jobs page lacks %q", want)
		}
	}
}

func TestPasswordSetQueuesSnapshots(t *testing.T) {
	e := newEnv(t, nil, true)
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(context.Background(), []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)
	wantRedirect(t, post(e.h, "/repos/password", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "password": {"repo secret"}}, nil), "/")
	if !slices.Equal(e.jobs.submitted, []string{"snapshots alice/main"}) {
		t.Errorf("submitted %v", e.jobs.submitted)
	}
}
