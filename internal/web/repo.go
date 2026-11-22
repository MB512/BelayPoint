package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/vault"
)

// Policies reads and stores retention policies (implemented by
// *store.Store).
type Policies interface {
	RepoPolicy(ctx context.Context, path string) (restic.Policy, bool, error)
	SetRepoPolicy(ctx context.Context, path string, p *restic.Policy) error
}

// PreviewTimeout bounds "forget --dry-run".
const PreviewTimeout = 5 * time.Minute

// repoData is the data of the repository page.
type repoData struct {
	Path, Owner string
	Password    bool
	Policy      restic.Policy
	Custom      bool // own policy, not the default
	Default     restic.Policy
	// Preview is set after "Preview forget".
	Preview *previewData
	Plan    *planData
}

type previewData struct {
	Keep, Remove int
	Groups       []previewGroup
}

type previewGroup struct {
	Host, Paths string
	Keep        []snapshotRow
	Remove      []snapshotRow
}

type snapshotRow struct {
	ID, Time, Tags string
}

func (s *server) repoPage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("repo")
	if _, ok := s.knownRepo(r.Context(), path); !ok {
		http.NotFound(w, r)
		return
	}
	d, err := s.repoData(r.Context(), path)
	if err != nil {
		s.Logger.Error("reading repository settings", "repo", path, "err", err)
		http.Error(w, "reading the repository settings failed; see the container log", http.StatusInternalServerError)
		return
	}
	s.renderRepo(w, r, http.StatusOK, d, "")
}

// repoData loads the saved settings of a repository.
func (s *server) repoData(ctx context.Context, path string) (*repoData, error) {
	p, custom, err := s.Policies.RepoPolicy(ctx, path)
	if err != nil {
		return &repoData{Path: path}, err
	}
	return &repoData{Path: path, Policy: p, Custom: custom}, nil
}

func (s *server) renderRepo(w http.ResponseWriter, r *http.Request, status int, d *repoData, errMsg string) {
	d.Owner = repos.Owner(d.Path)
	d.Password = s.Vault.Has(vault.RepoSecret(d.Path))
	d.Default = restic.DefaultPolicy
	if d.Plan == nil {
		plan, err := s.planFor(r.Context(), d.Path)
		if err != nil {
			s.Logger.Error("reading plan", "repo", d.Path, "err", err)
			plan = &planData{}
		}
		d.Plan = plan
	}
	s.render(w, status, "repo.html", page{
		Title: "Repository " + d.Path, CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg,
		Repo: d, JobsAvailable: s.Jobs != nil,
	})
}

// policyFromForm reads the keep fields; empty fields are 0.
func policyFromForm(f form) (restic.Policy, error) {
	num := func(name string) (int, error) {
		v := strings.TrimSpace(f.get(name))
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%w: %s is not a number", restic.ErrPolicy, strings.ReplaceAll(name, "_", " "))
		}
		return n, nil
	}
	var p restic.Policy
	var err error
	for _, field := range []struct {
		name string
		dst  *int
	}{
		{"keep_last", &p.KeepLast}, {"keep_hourly", &p.KeepHourly}, {"keep_daily", &p.KeepDaily},
		{"keep_weekly", &p.KeepWeekly}, {"keep_monthly", &p.KeepMonthly}, {"keep_yearly", &p.KeepYearly},
	} {
		if *field.dst, err = num(field.name); err != nil {
			return p, err
		}
	}
	p.KeepWithin = strings.TrimSpace(f.get("keep_within"))
	return p, p.Validate()
}

// setPolicy saves the policy, or with reset=yes returns to the default.
func (s *server) setPolicy(w http.ResponseWriter, r *http.Request) {
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
	var p *restic.Policy
	details := "default"
	if f.get("reset") != "yes" {
		pol, err := policyFromForm(f)
		if err != nil {
			s.renderRepo(w, r, http.StatusBadRequest, &repoData{Path: path, Policy: pol, Custom: true}, err.Error())
			return
		}
		p, details = &pol, strings.Join(pol.Args()[2:], " ")
	}
	if err := s.Policies.SetRepoPolicy(r.Context(), path, p); err != nil {
		s.Logger.Error("storing policy", "repo", path, "err", err)
		http.Error(w, "storing the policy failed; see the container log", http.StatusInternalServerError)
		return
	}
	s.Audit.Audit(r.Context(), "policy changed", path+": "+details+", "+remote(r))
	redirect(w, r, "/repos/view?repo="+url.QueryEscape(path))
}

// previewForget shows what forget with the policy in the form would
// remove. Nothing is changed or saved.
func (s *server) previewForget(w http.ResponseWriter, r *http.Request) {
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
	p, err := policyFromForm(f)
	_, custom, _ := s.Policies.RepoPolicy(r.Context(), path)
	d := &repoData{Path: path, Policy: p, Custom: custom}
	if err != nil {
		s.renderRepo(w, r, http.StatusBadRequest, d, err.Error())
		return
	}
	if s.Jobs == nil {
		s.renderRepo(w, r, http.StatusServiceUnavailable, d, "restic is not available; see the container log.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), PreviewTimeout)
	defer cancel()
	groups, err := s.Jobs.PreviewForget(ctx, path, p)
	if err != nil {
		status := jobErrorStatus(err)
		if !errors.Is(err, jobs.ErrSealed) && !errors.Is(err, jobs.ErrNoPassword) {
			s.Logger.Warn("forget preview", "repo", path, "err", err)
		}
		s.renderRepo(w, r, status, d, "Preview failed: "+err.Error())
		return
	}
	d.Preview = s.preview(groups)
	s.renderRepo(w, r, http.StatusOK, d, "")
}

func (s *server) preview(groups []restic.ForgetGroup) *previewData {
	rows := func(list []restic.Snapshot) []snapshotRow {
		out := make([]snapshotRow, 0, len(list))
		for _, sn := range list {
			out = append(out, snapshotRow{
				ID: sn.ShortID, Time: sn.Time.In(s.Location).Format("2006-01-02 15:04"),
				Tags: strings.Join(sn.Tags, ", "),
			})
		}
		return out
	}
	d := &previewData{}
	for _, g := range groups {
		d.Keep += len(g.Keep)
		d.Remove += len(g.Remove)
		d.Groups = append(d.Groups, previewGroup{
			Host: g.Host, Paths: strings.Join(g.Paths, ", "), Keep: rows(g.Keep), Remove: rows(g.Remove),
		})
	}
	return d
}

// maintenanceJobs are the jobs started from the repository page; the
// destructive ones need a confirmation page (CLAUDE.md, hard rules).
var maintenanceJobs = map[jobs.Type]bool{jobs.Forget: true, jobs.Prune: true, jobs.Check: false, jobs.Maintenance: true}

// maintenanceData is the data of the confirmation page.
type maintenanceData struct {
	Path   string
	Job    string
	Policy string // forget: the saved policy as restic arguments
	Custom bool
	Plan   string // maintenance: the enabled steps
}

func (s *server) maintenancePage(w http.ResponseWriter, r *http.Request) {
	path, typ := r.URL.Query().Get("repo"), jobs.Type(r.URL.Query().Get("job"))
	if _, ok := s.knownRepo(r.Context(), path); !ok || !maintenanceJobs[typ] {
		http.NotFound(w, r)
		return
	}
	d := &maintenanceData{Path: path, Job: string(typ)}
	if typ == jobs.Maintenance {
		p, err := s.Plans.RepoPlan(r.Context(), path)
		if err != nil {
			s.Logger.Error("reading plan", "repo", path, "err", err)
			http.Error(w, "reading the plan failed; see the container log", http.StatusInternalServerError)
			return
		}
		d.Plan = planSteps(p)
	}
	if typ == jobs.Forget || typ == jobs.Maintenance {
		p, custom, err := s.Policies.RepoPolicy(r.Context(), path)
		if err != nil {
			s.Logger.Error("reading policy", "repo", path, "err", err)
			http.Error(w, "reading the policy failed; see the container log", http.StatusInternalServerError)
			return
		}
		d.Policy, d.Custom = strings.Join(p.Args()[2:], " "), custom
	}
	s.render(w, http.StatusOK, "maintenance.html", page{
		Title: string(typ) + " " + path, CSRF: sessionFrom(r.Context()).CSRF, Maintenance: d,
	})
}

// startMaintenance queues forget, prune (both confirmed) or check.
func (s *server) startMaintenance(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	typ := jobs.Type(f.get("job"))
	destructive, known := maintenanceJobs[typ]
	if !known {
		http.NotFound(w, r)
		return
	}
	if destructive && f.get("confirm") != "yes" {
		http.Error(w, "not confirmed", http.StatusBadRequest)
		return
	}
	s.submitJob(w, r, f.get("repo"), typ)
}
