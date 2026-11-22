package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/scheduler"
	"github.com/MB512/belaypoint/internal/store"
)

// Plans reads and stores maintenance plans (implemented by *store.Store).
type Plans interface {
	RepoPlan(ctx context.Context, path string) (store.Plan, error)
	SetRepoPlan(ctx context.Context, path string, p store.Plan) error
}

// Schedule is the running scheduler (implemented by *scheduler.Scheduler).
type Schedule interface {
	Reload(ctx context.Context) error
	Next(repo string) time.Time
}

// planData is the plan section of the repository page.
type planData struct {
	store.Plan
	Next string // next run, "" if not scheduled
}

func (s *server) planFor(ctx context.Context, path string) (*planData, error) {
	p, err := s.Plans.RepoPlan(ctx, path)
	if err != nil {
		return nil, err
	}
	d := &planData{Plan: p}
	if s.Schedule != nil {
		if next := s.Schedule.Next(path); !next.IsZero() {
			d.Next = next.In(s.Location).Format("Mon 2006-01-02 15:04")
		}
	}
	return d, nil
}

// setPlan validates and stores the maintenance plan, then reloads the
// scheduler.
func (s *server) setPlan(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	path := f.get("repo")
	if _, ok := s.knownRepo(r.Context(), path); !ok {
		http.NotFound(w, r)
		return
	}
	p := store.Plan{
		Enabled:  f.get("enabled") == "yes",
		Schedule: strings.TrimSpace(f.get("schedule")),
		Unlock:   f.get("unlock") == "yes",
		Forget:   f.get("forget") == "yes",
		Prune:    f.get("prune") == "yes",
		Check:    f.get("check") == "yes",
	}
	fail := func(msg string) {
		d, _ := s.repoData(r.Context(), path)
		d.Plan = &planData{Plan: p}
		s.renderRepo(w, r, http.StatusBadRequest, d, msg)
	}
	t, err := strconv.Atoi(strings.TrimSpace(f.get("check_subset_t")))
	if err != nil || t < 0 || t > store.MaxCheckSubsetT {
		fail("The check rotation must be a number of runs between 0 and " + strconv.Itoa(store.MaxCheckSubsetT) + ".")
		return
	}
	p.CheckSubsetT = t
	if p.Enabled || p.Schedule != "" {
		if err := scheduler.Validate(p.Schedule); err != nil {
			fail(err.Error())
			return
		}
	}
	if p.Enabled && !p.Unlock && !p.Forget && !p.Prune && !p.Check {
		fail("Enable at least one step.")
		return
	}
	if err := s.Plans.SetRepoPlan(r.Context(), path, p); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		s.Logger.Error("storing plan", "repo", path, "err", err)
		http.Error(w, "storing the plan failed; see the container log", http.StatusInternalServerError)
		return
	}
	if s.Schedule != nil {
		if err := s.Schedule.Reload(r.Context()); err != nil {
			s.Logger.Error("reloading the schedule", "err", err)
		}
	}
	s.Audit.Audit(r.Context(), "plan changed", path+": "+planSummary(p)+", "+remote(r))
	redirect(w, r, "/repos/view?repo="+url.QueryEscape(path))
}

func planSummary(p store.Plan) string {
	if !p.Enabled {
		return "disabled"
	}
	return "\"" + p.Schedule + "\" " + planSteps(p) + ", check rotation " + strconv.Itoa(p.CheckSubsetT)
}

// planSteps lists the enabled steps, e.g. "unlock, forget, prune".
func planSteps(p store.Plan) string {
	var steps []string
	for _, st := range []struct {
		on   bool
		name string
	}{{p.Unlock, "unlock"}, {p.Forget, "forget"}, {p.Prune, "prune"}, {p.Check, "check"}} {
		if st.on {
			steps = append(steps, st.name)
		}
	}
	if len(steps) == 0 {
		return "no steps"
	}
	return strings.Join(steps, ", ")
}
