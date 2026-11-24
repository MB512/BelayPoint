package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MB512/belaypoint/internal/store"
)

func TestPlan(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	body := getWithCookie(e.h, "/repos/view?repo=alice/main&tab=schedule", cookie).Body.String()
	if !strings.Contains(body, "Not scheduled") || !strings.Contains(body, `name="check_subset_t" min="0" max="365" value="7"`) {
		t.Error("plan defaults not shown")
	}
	form := func(kv ...string) url.Values {
		v := url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "check_subset_t": {"7"}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for name, v := range map[string]url.Values{
		"too often":   form("enabled", "yes", "schedule", "*/5 * * * *", "forget", "yes"),
		"no steps":    form("enabled", "yes", "schedule", "0 3 * * *"),
		"bad cron":    form("enabled", "yes", "schedule", "daily", "forget", "yes"),
		"bad subset":  form("enabled", "yes", "schedule", "0 3 * * *", "forget", "yes", "check_subset_t", "x"),
		"@every":      form("enabled", "yes", "schedule", "@every 2h", "forget", "yes"),
		"subset >365": form("schedule", "0 3 * * *", "check_subset_t", "1000"),
	} {
		if w := post(e.h, "/repos/plan", cookie, v, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if p, _ := e.store.RepoPlan(ctx, "alice/main"); p.Enabled {
		t.Fatal("invalid plan stored")
	}

	v := form("enabled", "yes", "schedule", " 30 3 * * 0 ", "forget", "yes", "prune", "yes", "check", "yes", "check_subset_t", "5")
	wantRedirect(t, post(e.h, "/repos/plan", cookie, v, nil), "/repos/view?repo=alice%2Fmain&tab=schedule")
	p, _ := e.store.RepoPlan(ctx, "alice/main")
	want := store.Plan{Enabled: true, Schedule: "30 3 * * 0", Forget: true, Prune: true, Check: true, CheckSubsetT: 5, CheckSubsetN: 1}
	if p != want {
		t.Errorf("stored %+v", p)
	}
	if e.schedule.reloads != 1 || !e.audit.has("plan changed") {
		t.Errorf("reloads %d, audited %v", e.schedule.reloads, e.audit.has("plan changed"))
	}
	body = getWithCookie(e.h, "/repos/view?repo=alice/main&tab=schedule", cookie).Body.String()
	if !strings.Contains(body, "Next run: <strong>Sun 2026-11-29 03:30</strong>") {
		t.Error("next run not shown")
	}

	// The plan runs only on its schedule: there is no manual plan run.
	if w := getWithCookie(e.h, "/repos/maintenance?repo=alice/main&job=maintenance", cookie); w.Code != http.StatusNotFound {
		t.Errorf("manual plan run page: %d", w.Code)
	}
	if w := post(e.h, "/repos/maintenance", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "job": {"maintenance"}, "confirm": {"yes"}}, nil); w.Code != http.StatusNotFound || len(e.jobs.submitted) != 0 {
		t.Errorf("manual plan run: %d, submitted %v", w.Code, e.jobs.submitted)
	}

	// Disabling keeps the schedule text and needs no valid steps.
	wantRedirect(t, post(e.h, "/repos/plan", cookie, form("schedule", "30 3 * * 0"), nil), "/repos/view?repo=alice%2Fmain&tab=schedule")
	if p, _ := e.store.RepoPlan(ctx, "alice/main"); p.Enabled || p.Schedule != "30 3 * * 0" {
		t.Errorf("disabled: %+v", p)
	}
}
