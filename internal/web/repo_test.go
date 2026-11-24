package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/vault"
)

func TestRepoPageAndPolicy(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	w := getWithCookie(e.h, "/repos/view?repo=alice/main&tab=retention", cookie)
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

	wantRedirect(t, post(e.h, "/repos/policy", cookie, form(map[string]string{"keep_last": "3", "keep_within": "30d"}), nil), "/repos/view?repo=alice%2Fmain&tab=retention")
	if p, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); !custom || p.String() != (restic.Policy{Keep: restic.Keep{KeepLast: 3, KeepWithin: "30d"}}).String() {
		t.Errorf("stored %+v", p)
	}
	if !e.audit.has("policy changed") {
		t.Error("not audited")
	}
	wantRedirect(t, post(e.h, "/repos/policy", cookie, form(map[string]string{"reset": "yes"}), nil), "/repos/view?repo=alice%2Fmain&tab=retention")
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
	if len(e.jobs.previews) != 1 || e.jobs.previews[0] != "alice/main --keep-last 1" {
		t.Errorf("previews %v", e.jobs.previews)
	}
	// The preview does not save the policy.
	if _, custom, _ := e.store.RepoPolicy(ctx, "alice/main"); custom {
		t.Error("preview stored the policy")
	}
	if !strings.Contains(body, "Preview of the unsaved values") {
		t.Error("unsaved values not marked as unsaved")
	}
	// The saved (default) policy is previewed as such.
	saved := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "keep_daily": {"7"}, "keep_weekly": {"4"},
		"keep_monthly": {"12"}, "keep_yearly": {"3"}, "tag_1": {"pre-stop"}, "tag_1_last": {"2"}}
	if body := post(e.h, "/repos/forget-preview", cookie, saved, nil).Body.String(); !strings.Contains(body, "Preview of the saved policy") || strings.Contains(body, "not saved") {
		t.Error("saved policy previewed as unsaved")
	}
	e.jobs.err = jobs.ErrNoPassword
	if w := post(e.h, "/repos/forget-preview", cookie, v, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no password") {
		t.Errorf("without password: %d", w.Code)
	}
}

func TestMaintenance(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	w := getWithCookie(e.h, "/repos/maintenance?repo=alice/main&job=forget", cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "--keep-daily 7") {
		t.Errorf("forget confirm page: %d", w.Code)
	}
	for _, bad := range []string{"job=check", "job=unlock-all", "job=x", "job=forget&repo=../x"} {
		if w := getWithCookie(e.h, "/repos/maintenance?repo=alice/main&"+bad, cookie); w.Code != http.StatusNotFound && !strings.Contains(bad, "repo=") {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	v := func(job, confirm string) url.Values {
		x := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "job": {job}}
		if confirm != "" {
			x.Set("confirm", confirm)
		}
		return x
	}
	for _, job := range []string{"forget", "prune"} {
		if w := post(e.h, "/repos/maintenance", cookie, v(job, ""), nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s without confirmation: %d", job, w.Code)
		}
	}
	if w := post(e.h, "/repos/maintenance", cookie, v("unlock-all", "yes"), nil); w.Code != http.StatusNotFound {
		t.Errorf("unlock-all through maintenance: %d", w.Code)
	}
	wantRedirect(t, post(e.h, "/repos/maintenance", cookie, v("forget", "yes"), nil), "/")
	wantRedirect(t, post(e.h, "/repos/maintenance", cookie, v("prune", "yes"), nil), "/")
	wantRedirect(t, post(e.h, "/repos/maintenance", cookie, v("check", ""), nil), "/")
	withSubset := v("check", "")
	withSubset.Set("subset_n", "2")
	withSubset.Set("subset_t", "7")
	wantRedirect(t, post(e.h, "/repos/maintenance", cookie, withSubset, nil), "/")
	for _, bad := range [][2]string{{"8", "7"}, {"0", "7"}, {"1", ""}, {"", "7"}, {"1", "400"}, {"x", "7"}} {
		b := v("check", "")
		b.Set("subset_n", bad[0])
		b.Set("subset_t", bad[1])
		if w := post(e.h, "/repos/maintenance", cookie, b, nil); w.Code != http.StatusBadRequest {
			t.Errorf("check subset %v: %d", bad, w.Code)
		}
	}
	want := []string{"forget alice/main", "prune alice/main", "check alice/main", "check alice/main 2/7"}
	if strings.Join(e.jobs.submitted, ",") != strings.Join(want, ",") {
		t.Errorf("submitted %v", e.jobs.submitted)
	}
}

func TestTagRules(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	// The default policy shows its pre-stop rule (with ×), an empty row
	// (without ×) and the row for all other snapshots.
	body := getWithCookie(e.h, "/repos/view?repo=alice/main&tab=retention", cookie).Body.String()
	for _, want := range []string{`name="tag_1" value="pre-stop"`, `name="tag_1_last" min="0" value="2"`, `name="tag_2" value=""`,
		`name="remove_rule" value="1"`, "all other snapshots", `name="keep_daily" min="0" value="7"`, "tag pre-stop: --keep-last 2"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	if strings.Contains(body, `name="remove_rule" value="2"`) {
		t.Error("the empty row has a remove button")
	}

	v := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "keep_daily": {"7"},
		"tag_1": {"pre-stop"}, "tag_1_last": {"1"}, "tag_1_within": {"3d"},
		"tag_2": {"pre-restore"}, "tag_2_weekly": {"2"},
		"tag_3": {""}, "tag_3_within": {" "}} // empty row: ignored
	w := post(e.h, "/repos/forget-preview", cookie, v, nil)
	body = w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("preview: %d", w.Code)
	}
	for _, want := range []string{"Tag <code>pre-stop</code>: 1 removed", "Tag <code>pre-restore</code>: 1 removed",
		"All other snapshots: 2 removed, 1 kept", "Preview of the unsaved values", "4 of 5 snapshots would be removed"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview lacks %q", want)
		}
	}
	if e.jobs.previews[0] != "alice/main --keep-daily 7; tag pre-stop: --keep-last 1 --keep-within 3d; tag pre-restore: --keep-weekly 2" {
		t.Errorf("previewed %q", e.jobs.previews[0])
	}

	wantRedirect(t, post(e.h, "/repos/policy", cookie, v, nil), "/repos/view?repo=alice%2Fmain&tab=retention")
	p, _, _ := e.store.RepoPolicy(ctx, "alice/main")
	if len(p.TagRules) != 2 || p.TagRules[0].Tag != "pre-stop" || p.TagRules[0].KeepWithin != "3d" || p.TagRules[1].KeepWeekly != 2 {
		t.Errorf("stored %+v", p)
	}

	// Hourly and yearly are offered for tag rules too.
	v.Set("tag_2_hourly", "24")
	v.Set("tag_2_yearly", "1")
	wantRedirect(t, post(e.h, "/repos/policy", cookie, v, nil), "/repos/view?repo=alice%2Fmain&tab=retention")
	p, _, _ = e.store.RepoPolicy(ctx, "alice/main")
	if len(p.TagRules) != 2 || p.TagRules[1].KeepHourly != 24 || p.TagRules[1].KeepYearly != 1 {
		t.Errorf("stored %+v", p)
	}
	body = getWithCookie(e.h, "/repos/view?repo=alice/main&tab=retention", cookie).Body.String()
	for _, want := range []string{`name="tag_2_hourly" min="0" value="24"`, `name="tag_2_yearly" min="0" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}

	// The × of row 1 saves the policy without that rule.
	v.Set("remove_rule", "1")
	wantRedirect(t, post(e.h, "/repos/policy", cookie, v, nil), "/repos/view?repo=alice%2Fmain&tab=retention")
	p, _, _ = e.store.RepoPolicy(ctx, "alice/main")
	if len(p.TagRules) != 1 || p.TagRules[0].Tag != "pre-restore" || p.KeepDaily != 7 {
		t.Errorf("after removing rule 1: %+v", p)
	}

	for name, bad := range map[string]url.Values{
		"values without tag": {"tag_1": {""}, "tag_1_last": {"5"}},
		"rule without keep":  {"tag_1": {"pre-stop"}},
		"tag list":           {"tag_1": {"a,b"}, "tag_1_last": {"1"}},
		"twice":              {"tag_1": {"x"}, "tag_1_last": {"1"}, "tag_2": {"x"}, "tag_2_last": {"1"}},
		"bad number":         {"tag_1": {"x"}, "tag_1_last": {"one"}},
	} {
		bad.Set("csrf_token", csrf)
		bad.Set("repo", "alice/main")
		bad.Set("keep_daily", "7")
		if w := post(e.h, "/repos/policy", cookie, bad, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

// The repository page has three tabs; only the active one is rendered.
// Run now needs the repository password.
func TestRepoTabs(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)

	page := func(tab string) string {
		w := getWithCookie(e.h, "/repos/view?repo=alice/main"+tab, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("tab %q: %d", tab, w.Code)
		}
		return w.Body.String()
	}
	if body := page(""); !strings.Contains(body, "Set the <a") || strings.Contains(body, "Forget…") {
		t.Error("run tab without password offers jobs")
	}
	e.vault.secrets = []string{vault.RepoSecret("alice/main")}
	for tab, c := range map[string]struct{ want, not []string }{
		"":               {[]string{`tab=run" aria-current="page"`, "Unlock", "Remove all locks…", "Forget…", "Prune…", `name="subset_n"`}, []string{"all other snapshots", "Save plan", "Run plan now"}},
		"&tab=x":         {[]string{`tab=run" aria-current="page"`}, nil},
		"&tab=retention": {[]string{`tab=retention" aria-current="page"`, "all other snapshots", "Preview these values"}, []string{"Forget…", "Save plan"}},
		"&tab=schedule":  {[]string{`tab=schedule" aria-current="page"`, "Save plan"}, []string{"Forget…", "all other snapshots"}},
	} {
		body := page(tab)
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("tab %q lacks %q", tab, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(body, n) {
				t.Errorf("tab %q has %q", tab, n)
			}
		}
	}
}
