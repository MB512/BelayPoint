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
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// Policies reads and stores retention policies (implemented by
// *store.Store).
type Policies interface {
	RepoPolicy(ctx context.Context, path string) (restic.Policy, bool, error)
	SetRepoPolicy(ctx context.Context, path string, p *restic.Policy) error
}

// RepoFlags reads and stores the per-repository marks (implemented by
// *store.Store).
type RepoFlags interface {
	RepoFlags(ctx context.Context, path string) (store.RepoFlags, error)
	SetRepoArchived(ctx context.Context, path string, archived bool) error
	SetRepoOwnerKey(ctx context.Context, path string, ownerKey bool) error
}

// PreviewTimeout bounds "forget --dry-run".
const PreviewTimeout = 5 * time.Minute

// repoData is the data of the repository page.
type repoData struct {
	Path, Owner string
	Password    bool
	Policy      restic.Policy
	TagRows     []tagRow
	Custom      bool // own policy, not the default
	Archived    bool // closed repository: no new backups expected
	OwnerKey    bool // the owner keeps the password; nothing runs here
	Default     restic.Policy
	// Tab is the visible tab: tabRun, tabRetention or tabSchedule.
	Tab string
	// Locks are the repository's lock files, read live for the Run now tab.
	Locks *repoRow
	// Preview is set after "Preview these values".
	Preview *previewData
	Plan    *planData
}

// The tabs of the repository page (query parameter tab). Only the active
// tab is rendered; the tabs are plain links, no JavaScript.
const (
	tabRun       = "run"
	tabRetention = "retention"
	tabSchedule  = "schedule"
)

// repoTab returns the tab named in the query, tabRun if unknown.
func repoTab(name string) string {
	// Returning the constants (not name) keeps user input out of redirect
	// targets.
	switch name {
	case tabRetention:
		return tabRetention
	case tabSchedule:
		return tabSchedule
	}
	return tabRun
}

type previewData struct {
	Keep, Remove int
	Passes       []previewPass
	// Unsaved is set when the previewed values differ from the saved
	// policy, so the page does not pretend they are in effect.
	Unsaved bool
}

// previewPass is one forget pass: a tag rule (Tag set) or the main policy.
type previewPass struct {
	Tag          string
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
	d.Tab = repoTab(r.URL.Query().Get("tab"))
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
	if flags, err := s.Flags.RepoFlags(r.Context(), d.Path); err != nil {
		s.Logger.Error("reading repository flags", "repo", d.Path, "err", err)
	} else {
		d.Archived, d.OwnerKey = flags.Archived, flags.OwnerKey
	}
	d.Password = s.Vault.Has(vault.RepoSecret(d.Path))
	d.Default = restic.DefaultPolicy
	d.TagRows = tagRows(d.Policy)
	if d.Tab == "" {
		d.Tab = tabRun
	}
	if d.Tab == tabRun {
		d.Locks = &repoRow{Path: d.Path}
		s.addLocks(d.Locks, time.Now())
	}
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

// policyFromForm reads the "all other snapshots" row (keep_<field>) and the
// tag rule rows (tag_<i>, tag_<i>_<field>); empty fields are 0. Empty rows
// are ignored; remove_rule=<i> (the row's × button) leaves rule i out.
func policyFromForm(f form) (restic.Policy, error) {
	num := func(name, label string) (int, error) {
		v := strings.TrimSpace(f.get(name))
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%w: %s is not a number", restic.ErrPolicy, label)
		}
		return n, nil
	}
	keep := func(prefix, label string) (restic.Keep, error) {
		var k restic.Keep
		dst := map[string]*int{
			"last": &k.KeepLast, "hourly": &k.KeepHourly, "daily": &k.KeepDaily,
			"weekly": &k.KeepWeekly, "monthly": &k.KeepMonthly, "yearly": &k.KeepYearly,
		}
		for _, name := range numericKeepFields {
			n, err := num(prefix+name, label+"keep "+name)
			if err != nil {
				return k, err
			}
			*dst[name] = n
		}
		k.KeepWithin = strings.TrimSpace(f.get(prefix + "within"))
		return k, nil
	}
	var p restic.Policy
	var err error
	if p.Keep, err = keep("keep_", ""); err != nil {
		return p, err
	}
	var rowErr error // reported after reading all rows, so the form keeps them
	removed := f.get("remove_rule")
	for i := 1; i <= restic.MaxTagRules; i++ {
		index := strconv.Itoa(i)
		if index == removed {
			continue // the row's × button: save without this rule
		}
		prefix := "tag_" + index
		tag := strings.TrimSpace(f.get(prefix))
		if tag == "" {
			// A row with values but no tag is a mistake (rules are removed
			// with ×), not a reason to drop the values silently.
			for _, name := range append(numericKeepFields, "within") {
				if rowErr == nil && strings.TrimSpace(f.get(prefix+"_"+name)) != "" {
					rowErr = fmt.Errorf("%w: row %d has values but no tag; enter a tag or clear the row", restic.ErrPolicy, i)
				}
			}
			continue
		}
		k, err := keep(prefix+"_", "tag "+tag+": ")
		if err != nil {
			return p, err
		}
		p.TagRules = append(p.TagRules, restic.TagRule{Tag: tag, Keep: k})
	}
	if rowErr != nil {
		return p, rowErr
	}
	return p, p.Validate()
}

// numericKeepFields are the field name suffixes of a policy row's numbers;
// each row also has "within".
var numericKeepFields = []string{"last", "hourly", "daily", "weekly", "monthly", "yearly"}

// tagRow is one row of the tag rule table; the form always has an empty
// row to add a rule, up to restic.MaxTagRules.
type tagRow struct {
	Index                                        int
	Tag                                          string
	Last, Hourly, Daily, Weekly, Monthly, Yearly string
	Within                                       string
}

func tagRows(p restic.Policy) []tagRow {
	n := func(v int) string {
		if v == 0 {
			return ""
		}
		return strconv.Itoa(v)
	}
	var rows []tagRow
	for i, r := range p.TagRules {
		rows = append(rows, tagRow{
			Index: i + 1, Tag: r.Tag, Last: n(r.KeepLast), Hourly: n(r.KeepHourly), Daily: n(r.KeepDaily),
			Weekly: n(r.KeepWeekly), Monthly: n(r.KeepMonthly), Yearly: n(r.KeepYearly), Within: r.KeepWithin,
		})
	}
	if len(rows) < restic.MaxTagRules {
		rows = append(rows, tagRow{Index: len(rows) + 1})
	}
	return rows
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
			s.renderRepo(w, r, http.StatusBadRequest, &repoData{Path: path, Policy: pol, Custom: true, Tab: tabRetention}, err.Error())
			return
		}
		p, details = &pol, pol.String()
	}
	if err := s.Policies.SetRepoPolicy(r.Context(), path, p); err != nil {
		s.Logger.Error("storing policy", "repo", path, "err", err)
		http.Error(w, "storing the policy failed; see the container log", http.StatusInternalServerError)
		return
	}
	s.Audit.Audit(r.Context(), "policy changed", path+": "+details+", "+remote(r))
	redirect(w, r, "/repos/view?repo="+url.QueryEscape(path)+"&tab="+tabRetention)
}

// setArchived marks a repository as an archive (archived=yes) or as
// active, and returns to the tab it was changed on.
func (s *server) setArchived(w http.ResponseWriter, r *http.Request) {
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
	archived := f.get("archived") == "yes"
	if err := s.Flags.SetRepoArchived(r.Context(), path, archived); err != nil {
		s.Logger.Error("storing archive flag", "repo", path, "err", err)
		http.Error(w, "storing the archive flag failed; see the container log", http.StatusInternalServerError)
		return
	}
	event := "repository marked as active"
	if archived {
		event = "repository marked as archive"
	}
	s.Audit.Audit(r.Context(), event, path+", "+remote(r))
	redirect(w, r, "/repos/view?repo="+url.QueryEscape(path)+"&tab="+repoTab(f.get("tab")))
}

// setOwnerKey marks that the owner keeps the password (ownerkey=yes), so
// the repository is not reported for a missing one, or removes the mark.
// The mark contradicts a stored password, so it needs none to be stored.
func (s *server) setOwnerKey(w http.ResponseWriter, r *http.Request) {
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
	on := f.get("ownerkey") == "yes"
	if on && s.Vault.Has(vault.RepoSecret(path)) {
		d, _ := s.repoData(r.Context(), path)
		s.renderRepo(w, r, http.StatusConflict, d, "A password is stored for this repository. Remove it on the password page first.")
		return
	}
	if err := s.Flags.SetRepoOwnerKey(r.Context(), path, on); err != nil {
		s.Logger.Error("storing owner key flag", "repo", path, "err", err)
		http.Error(w, "storing the flag failed; see the container log", http.StatusInternalServerError)
		return
	}
	event := "repository mark removed: owner keeps the password"
	if on {
		event = "repository marked: owner keeps the password"
	}
	s.Audit.Audit(r.Context(), event, path+", "+remote(r))
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
	saved, custom, _ := s.Policies.RepoPolicy(r.Context(), path)
	d := &repoData{Path: path, Policy: p, Custom: custom, Tab: tabRetention}
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
	results, err := s.Jobs.PreviewForget(ctx, path, p)
	if err != nil {
		status := jobErrorStatus(err)
		if !errors.Is(err, jobs.ErrSealed) && !errors.Is(err, jobs.ErrNoPassword) {
			s.Logger.Warn("forget preview", "repo", path, "err", err)
		}
		s.renderRepo(w, r, status, d, "Preview failed: "+err.Error())
		return
	}
	d.Preview = s.preview(results)
	// String lists every keep value and tag rule as restic arguments, so
	// equal strings mean equal policies.
	d.Preview.Unsaved = p.String() != saved.String()
	s.renderRepo(w, r, http.StatusOK, d, "")
}

func (s *server) preview(results []restic.PassResult) *previewData {
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
	d := &previewData{Keep: len(restic.Kept(results)), Remove: restic.Removed(results)}
	for _, r := range results {
		pass := previewPass{Tag: r.Tag}
		for _, g := range r.Groups {
			pass.Keep += len(g.Keep)
			pass.Remove += len(g.Remove)
			pass.Groups = append(pass.Groups, previewGroup{
				Host: g.Host, Paths: strings.Join(g.Paths, ", "), Keep: rows(g.Keep), Remove: rows(g.Remove),
			})
		}
		d.Passes = append(d.Passes, pass)
	}
	return d
}

// maintenanceJobs are the jobs started from the repository page; the
// destructive ones need a confirmation page (CLAUDE.md, hard rules).
var maintenanceJobs = map[jobs.Type]bool{jobs.Forget: true, jobs.Prune: true, jobs.Check: false}

// maintenanceData is the data of the confirmation page.
type maintenanceData struct {
	Path   string
	Job    string
	Policy string // forget: the saved policy as restic arguments
	Custom bool
	// forget: the dry-run with the saved policy. Without a preview
	// (PreviewErr set) the page offers no confirmation.
	Preview    *previewData
	PreviewErr string
}

func (s *server) maintenancePage(w http.ResponseWriter, r *http.Request) {
	path, typ := r.URL.Query().Get("repo"), jobs.Type(r.URL.Query().Get("job"))
	if _, ok := s.knownRepo(r.Context(), path); !ok || !maintenanceJobs[typ] {
		http.NotFound(w, r)
		return
	}
	d := &maintenanceData{Path: path, Job: string(typ)}
	if typ == jobs.Forget {
		p, custom, err := s.Policies.RepoPolicy(r.Context(), path)
		if err != nil {
			s.Logger.Error("reading policy", "repo", path, "err", err)
			http.Error(w, "reading the policy failed; see the container log", http.StatusInternalServerError)
			return
		}
		d.Policy, d.Custom = p.String(), custom
		d.Preview, d.PreviewErr = s.forgetDryRun(r.Context(), path, p)
	}
	s.render(w, http.StatusOK, "maintenance.html", page{
		Title: string(typ) + " " + path, CSRF: sessionFrom(r.Context()).CSRF, Maintenance: d,
	})
}

// forgetDryRun runs forget --dry-run with the saved policy for the
// confirmation page, so nobody confirms a forget without seeing what it
// removes. On failure it returns the message to show instead.
func (s *server) forgetDryRun(ctx context.Context, path string, p restic.Policy) (*previewData, string) {
	if s.Jobs == nil {
		return nil, "restic is not available; see the container log."
	}
	ctx, cancel := context.WithTimeout(ctx, PreviewTimeout)
	defer cancel()
	results, err := s.Jobs.PreviewForget(ctx, path, p)
	if err != nil {
		if !errors.Is(err, jobs.ErrSealed) && !errors.Is(err, jobs.ErrNoPassword) {
			s.Logger.Warn("forget preview", "repo", path, "err", err)
		}
		return nil, "The preview (dry-run) failed: " + err.Error()
	}
	return s.preview(results), ""
}

// startMaintenance queues forget, prune (both confirmed) or check (with an
// optional data subset: subset_n of subset_t).
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
	if typ == jobs.Check {
		s.submitCheck(w, r, f)
		return
	}
	s.submitJob(w, r, f.get("repo"), typ, true)
}
