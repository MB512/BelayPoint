package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/restic"
)

func TestRepoPageAndPolicy(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	w := getWithCookie(e.h, "/repos/view?repo=alice/main", cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "The default policy applies") || !strings.Contains(w.Body.String(), `name="keep_daily" min="0" value="7"`) {
		t.Fatalf("page: %d", w.Code)
	}
	if w := getWithCookie(e.h, "/repos/view?repo=../etc", cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown repository: %d", w.Code)
	}

	form := func(extra map[string]string) url.Values {
		v := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}}
		for k, x := range extra {
			v.Set(k, x)
		}
		return v
	}
	// Invalid policies are refused and not stored.
	for _, bad := range []map[string]string{
		{},
		{"keep_daily": "seven"},
		{"keep_within": "1y; touch /tmp/x"},
		{"keep_daily": "-1"},
	} {
		if w := post(e.h, "/repos/policy", cookie, form(bad), nil); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", bad, w.Code)
		}
	}
	if _, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); custom {
		t.Fatal("invalid policy stored")
	}

	wantRedirect(t, post(e.h, "/repos/policy", cookie, form(map[string]string{"keep_last": "3", "keep_within": "30d"}), nil), "/repos/view?repo=alice%2Fmain")
	if p, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); !custom || p != (restic.Policy{KeepLast: 3, KeepWithin: "30d"}) {
		t.Errorf("stored %+v", p)
	}
	if !e.audit.has("policy changed") {
		t.Error("not audited")
	}
	wantRedirect(t, post(e.h, "/repos/policy", cookie, form(map[string]string{"reset": "yes"}), nil), "/repos/view?repo=alice%2Fmain")
	if _, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); custom {
		t.Error("reset failed")
	}
}

func TestForgetPreview(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	v := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "keep_last": {"1"}}
	w := post(e.h, "/repos/forget-preview", cookie, v, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", w.Code, body)
	}
	for _, want := range []string{"2 of 3 snapshots would be removed", "gone0002", "keep0001", "pc&lt;1&gt;", `name="keep_last" min="0" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("preview lacks %q", want)
		}
	}
	if len(e.jobs.previews) != 1 || e.jobs.previews[0] != "alice/main --group-by host,paths --keep-last 1" {
		t.Errorf("previews %v", e.jobs.previews)
	}
	// The preview does not save the policy.
	if _, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); custom {
		t.Error("preview stored the policy")
	}
	e.jobs.err = jobs.ErrNoPassword
	if w := post(e.h, "/repos/forget-preview", cookie, v, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no password") {
		t.Errorf("without password: %d", w.Code)
	}
}
