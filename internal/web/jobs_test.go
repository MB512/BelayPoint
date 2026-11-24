package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

func TestUnlock(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	wantRedirect(t, post(e.h, "/repos/unlock", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}}, nil), "/jobs/1/log")
	if w := post(e.h, "/repos/unlock", cookie, url.Values{"csrf_token": {csrf}, "repo": {"../x"}}, nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown repository: %d", w.Code)
	}

	// unlock --remove-all needs the typed name.
	if w := getWithCookie(e.h, "/repos/unlock-all?repo=alice/main", cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "confirm_name") {
		t.Errorf("confirm page: %d", w.Code)
	}
	w := post(e.h, "/repos/unlock-all", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "confirm_name": {"alice"}}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("wrong name: %d", w.Code)
	}
	wantRedirect(t, post(e.h, "/repos/unlock-all", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "confirm_name": {"alice/main"}}, nil), "/jobs/2/log")
	if !slices.Equal(e.jobs.submitted, []string{"unlock alice/main", "unlock-all alice/main"}) || !e.audit.has("job submitted") {
		t.Errorf("submitted %v", e.jobs.submitted)
	}

	// Started on the repository page (from=repo): errors are shown there,
	// and the unlock-all page returns there on cancel.
	e.jobs.err = jobs.ErrBusy
	if body := post(e.h, "/repos/unlock", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "from": {"repo"}}, nil).Body.String(); !strings.Contains(body, `tab=run" aria-current="page"`) || !strings.Contains(body, "already queued or running") {
		t.Error("refused unlock not shown on the repository page")
	}
	e.jobs.err = nil
	body := getWithCookie(e.h, "/repos/unlock-all?repo=alice/main&from=repo", cookie).Body.String()
	if !strings.Contains(body, `name="from" value="repo"`) || !strings.Contains(body, `href="/repos/view?repo=alice%2fmain">Cancel`) {
		t.Error("unlock-all page from the repository page does not return there")
	}
	wantRedirect(t, post(e.h, "/repos/unlock-all", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "confirm_name": {"alice/main"}, "from": {"repo"}}, nil), "/jobs/3/log")
}

func TestJobLogPage(t *testing.T) {
	e := newEnv(t, nil, true)
	cookie := login(t, e)
	_ = os.WriteFile(jobs.LogPath(e.logDir, 7), []byte("restic says <hi>\n"), 0o600)
	w := getWithCookie(e.h, "/jobs/7/log", cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "restic says &lt;hi&gt;") {
		t.Errorf("log page: %d", w.Code)
	}
	if w := getWithCookie(e.h, "/jobs/8/log", cookie); !strings.Contains(w.Body.String(), "no log") {
		t.Error("missing log not explained")
	}

	// With a job record: state and result; while queued or running the
	// page reloads itself.
	ctx := context.Background()
	t0 := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	queued, _ := e.store.AddJob(ctx, "alice/main", "prune", "manual", t0)
	body := getWithCookie(e.h, fmt.Sprintf("/jobs/%d/log", queued), cookie).Body.String()
	for _, want := range []string{`<meta http-equiv="refresh" content="2">`, ">queued<", "(waiting in the queue)", "<strong>prune</strong>", "Back to the repository"} {
		if !strings.Contains(body, want) {
			t.Errorf("queued job page lacks %q", want)
		}
	}
	_ = e.store.StartJob(ctx, queued, t0.Add(time.Second))
	_ = e.store.FinishJob(ctx, queued, jobs.StateFailed, "", "disk full", t0.Add(3*time.Second))
	body = getWithCookie(e.h, fmt.Sprintf("/jobs/%d/log", queued), cookie).Body.String()
	for _, want := range []string{">failed<", "disk full", "after 2s"} {
		if !strings.Contains(body, want) {
			t.Errorf("finished job page lacks %q", want)
		}
	}
	if strings.Contains(body, "http-equiv") {
		t.Error("finished job page still reloads")
	}
	for _, bad := range []string{"/jobs/abc/log", "/jobs/-1/log", "/jobs/..%2f..%2fetc/log"} {
		if w := getWithCookie(e.h, bad, cookie); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
}

func TestReadTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l")
	_ = os.WriteFile(p, []byte("0123456789"), 0o600)
	if s, tr, err := readTail(p, 4); s != "6789" || !tr || err != nil {
		t.Errorf("tail = %q %v %v", s, tr, err)
	}
	if s, tr, _ := readTail(p, 100); s != "0123456789" || tr {
		t.Errorf("whole = %q %v", s, tr)
	}
}
