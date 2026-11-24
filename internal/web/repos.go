package web

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// StaleLockAge is the lock file age from which the UI warns (and, later,
// notifications fire).
const StaleLockAge = 24 * time.Hour

// StaleBackupAge is the age of the newest snapshot from which an active
// (not archived) repository is listed under "Needs attention".
const StaleBackupAge = 7 * 24 * time.Hour

// maintenanceTypes are the job types shown as the maintenance status.
var maintenanceTypes = []string{string(jobs.Maintenance), string(jobs.Forget), string(jobs.Prune), string(jobs.Check)}

type repoRow struct {
	Path     string
	Owner    string
	Missing  bool
	Size     string // "" until measured
	Bytes    int64
	Files    int64
	Measured string
	Locks    int
	// OldestLock is the age of the oldest lock file ("" if none);
	// StaleLock is true when it is older than StaleLockAge.
	OldestLock string
	StaleLock  bool
	LockError  bool
	Password   bool
	// SnapshotsTitle says when the snapshots were listed.
	SnapshotsTitle string
	// Busy: a job for this repository is queued or running.
	Busy bool
	// Archived: closed repository, no new backups expected.
	Archived bool
	// OwnerKey: the owner keeps the password; the overview reads the
	// snapshot files instead of restic's listing.
	OwnerKey bool

	// Overview columns. Name is the path without the user.
	Name string
	// LastBackup is the age of the newest snapshot ("3 days ago",
	// "Feb 2019"); "" until listed. StaleBackup marks an active repository
	// whose newest snapshot is older than StaleBackupAge.
	LastBackup      string
	LastBackupTitle string
	StaleBackup     bool
	SnapshotCount   string
	// Maintenance: the newest maintenance job (nil if none) and the next
	// scheduled run ("" if none).
	LastJob *lastJob
	NextRun string
}

// lastJob is the maintenance status of a repository on the overview.
type lastJob struct {
	ID         int64
	Type, When string
	State      string
	OK         bool // succeeded
	Active     bool // queued or running
}

// overviewData groups the repositories per user and lists what needs
// attention.
type overviewData struct {
	Attention []attention
	Groups    []repoGroup
}

type repoGroup struct {
	Owner string
	Size  string // sum of the measured repositories
	Repos []repoRow
}

// attention is one line of "Needs attention": the repository, what is
// wrong and where to fix it. Forget offers the "Remove from BelayPoint"
// button of a missing repository instead of a link.
type attention struct {
	Path, Problem, Action, Link string
	Forget                      bool
}

// home is the overview: all known repositories with what can be read
// without their password.
func (s *server) home(w http.ResponseWriter, r *http.Request) {
	s.renderHome(w, r, http.StatusOK, "")
}

func (s *server) renderHome(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		http.Error(w, "listing repositories failed; see the container log", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	p := page{
		Title: "Overview", CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg,
		Scanning: s.Scanner.Scanning(), JobsAvailable: s.Jobs != nil,
	}
	last, err := s.JobList.LastJobs(r.Context(), maintenanceTypes)
	if err != nil {
		s.Logger.Error("reading last jobs", "err", err)
	}
	for _, repo := range list {
		row := repoRow{
			Path:     repo.Path,
			Owner:    repos.Owner(repo.Path),
			Missing:  repo.Missing,
			Password: s.Vault.Has(vault.RepoSecret(repo.Path)),
			Archived: repo.Archived,
			OwnerKey: repo.OwnerKey,
		}
		row.Name = strings.TrimPrefix(repo.Path, row.Owner+"/")
		if repo.Usage != nil {
			row.Size = formatBytes(repo.Usage.Bytes)
			row.Bytes = repo.Usage.Bytes
			row.Files = repo.Usage.Files
			row.Measured = repo.UsageTime.In(s.Location).Format("2006-01-02 15:04")
		}
		if sn := repo.Snapshots; sn != nil {
			row.SnapshotCount = strconv.Itoa(sn.Count)
			row.SnapshotsTitle = "listed " + sn.Time.In(s.Location).Format("2006-01-02 15:04")
			if !sn.Newest.IsZero() {
				row.LastBackup = humanAge(now, sn.Newest, s.Location)
				row.LastBackupTitle = sn.Newest.In(s.Location).Format("2006-01-02 15:04")
				row.StaleBackup = !repo.Archived && now.Sub(sn.Newest) > StaleBackupAge
			}
		}
		if row.OwnerKey && !row.Password && !repo.Missing {
			s.addSnapshotFiles(&row, now)
		}
		if j, ok := last[repo.Path]; ok {
			row.LastJob = &lastJob{
				ID: j.ID, Type: j.Type, State: j.State, OK: j.State == jobs.StateSucceeded,
				Active: j.State == jobs.StateQueued || j.State == jobs.StateRunning,
				When:   humanAge(now, cmp.Or(j.Finished, j.Started, j.Queued), s.Location),
			}
		}
		if !repo.Missing {
			s.addLocks(&row, now)
			row.Busy = s.Jobs != nil && s.Jobs.Busy(repo.Path)
			if s.Schedule != nil {
				if next := s.Schedule.Next(repo.Path); !next.IsZero() {
					row.NextRun = next.In(s.Location).Format("Mon 02 Jan 15:04")
				}
			}
		}
		p.Repos = append(p.Repos, row)
	}
	_, p.Total = summarize(p.Repos)
	p.Overview = overview(p.Repos)
	s.render(w, status, "home.html", p)
}

// ownerRow is one line of the per-user summary; the total uses it too.
type ownerRow struct {
	Name     string
	Repos    int
	Bytes    int64
	Size     string
	Files    int64
	Share    string
	MaxBytes int64 // largest repository (total) or user (owner rows)
	// Unmeasured counts repositories without disk usage yet; their size
	// is not in the sum.
	Unmeasured int
}

// summarize sums the present repositories per user, largest first, and in
// total. Missing repositories are left out: their last usage is outdated.
func summarize(rows []repoRow) ([]ownerRow, ownerRow) {
	var total ownerRow
	byName := map[string]*ownerRow{}
	var owners []*ownerRow
	for _, r := range rows {
		if r.Missing {
			continue
		}
		o := byName[r.Owner]
		if o == nil {
			o = &ownerRow{Name: r.Owner}
			byName[r.Owner] = o
			owners = append(owners, o)
		}
		for _, sum := range []*ownerRow{o, &total} {
			sum.Repos++
			if r.Size == "" {
				sum.Unmeasured++
				continue
			}
			sum.Bytes += r.Bytes
			sum.Files += r.Files
		}
		total.MaxBytes = max(total.MaxBytes, r.Bytes)
	}
	// slices.SortFunc with a comparison func is like List.Sort(Comparison)
	// in C#; cmp.Or picks the first non-zero result (then by name).
	slices.SortFunc(owners, func(a, b *ownerRow) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Name, b.Name))
	})
	out := make([]ownerRow, 0, len(owners))
	for _, o := range owners {
		o.MaxBytes = owners[0].Bytes
		o.Size = formatBytes(o.Bytes)
		o.Share = percent(o.Bytes, total.Bytes)
		out = append(out, *o)
	}
	total.Size = formatBytes(total.Bytes)
	return out, total
}

// percent formats part/whole as a whole percentage; "< 1 %" for small
// non-zero parts.
func percent(part, whole int64) string {
	if whole <= 0 {
		return ""
	}
	p := part * 100 / whole
	if p == 0 && part > 0 {
		return "< 1 %"
	}
	return fmt.Sprintf("%d %%", p)
}

// addSnapshotFiles fills the snapshot columns of a repository whose owner
// keeps the password from its snapshot files (count and newest write time,
// read live): without the password this is when it was last appended to.
func (s *server) addSnapshotFiles(row *repoRow, now time.Time) {
	dir, err := repos.Dir(s.ReposDir, row.Path)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		return
	}
	n, newest, err := repos.SnapshotFiles(dir)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		return
	}
	row.SnapshotCount = strconv.Itoa(n)
	row.SnapshotsTitle = "snapshot files, read live"
	if !newest.IsZero() {
		row.LastBackup = humanAge(now, newest, s.Location)
		row.LastBackupTitle = "newest snapshot file written " + newest.In(s.Location).Format("2006-01-02 15:04")
		row.StaleBackup = !row.Archived && now.Sub(newest) > StaleBackupAge
	}
}

// addLocks reads the lock files of the repository live (one directory
// listing, cheap).
func (s *server) addLocks(row *repoRow, now time.Time) {
	dir, err := repos.Dir(s.ReposDir, row.Path)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		row.LockError = true
		return
	}
	locks, err := repos.Locks(dir)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		row.LockError = true
		return
	}
	row.Locks = len(locks)
	if len(locks) > 0 {
		age := now.Sub(locks[0].ModTime)
		row.OldestLock = formatAge(age)
		row.StaleLock = age > StaleLockAge
	}
}

// rescan starts discovery and disk usage in the background.
func (s *server) rescan(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	toStorage := f.get("from") == "storage"
	f.wipe()
	if s.Scanner.Rescan() {
		s.Audit.Audit(r.Context(), "rescan", remote(r))
	}
	if toStorage {
		redirect(w, r, "/storage")
		return
	}
	redirect(w, r, "/")
}

// formatBytes formats n with binary units (KiB, MiB, ...), as restic does.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatAge formats a duration coarsely: "45 s", "12 min", "5 h", "3 d".
func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d d", int(d.Hours()/24))
	}
}

// forgetMissingRepo removes a repository that discovery no longer finds
// from BelayPoint: its database record (policy, plan, flags), its stored
// password and its schedule. Nothing below the repository root is touched;
// the job history stays. A repository whose directory exists again (no
// rescan since) is refused.
func (s *server) forgetMissingRepo(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	path := f.get("repo")
	// repos.Dir checks every path component on disk: no error means the
	// directory exists again.
	if _, err := repos.Dir(s.ReposDir, path); err == nil {
		s.renderHome(w, r, http.StatusConflict, path+" exists again below the repository root; rescan instead of removing it.")
		return
	}
	switch err := s.Repos.DeleteMissingRepo(r.Context(), path); {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrNotMissing):
		s.renderHome(w, r, http.StatusConflict, path+" is still present; only missing repositories can be removed.")
		return
	case err != nil:
		s.Logger.Error("removing repository", "repo", path, "err", err)
		http.Error(w, "removing the repository failed; see the container log", http.StatusInternalServerError)
		return
	}
	details := path
	if s.Vault.Has(vault.RepoSecret(path)) {
		if err := s.Vault.DeleteSecret(vault.RepoSecret(path)); err != nil {
			s.Logger.Error("removing repository password", "repo", path, "err", err)
		} else {
			details += ", its stored password too"
		}
	}
	if s.Schedule != nil {
		if err := s.Schedule.Reload(r.Context()); err != nil {
			s.Logger.Error("reloading the schedule", "err", err)
		}
	}
	s.Audit.Audit(r.Context(), "missing repository removed", details+", "+remote(r))
	redirect(w, r, "/")
}

// overview groups the rows per user (users and repositories by name, as
// listed) and collects what needs attention, in table order.
func overview(rows []repoRow) *overviewData {
	d := &overviewData{}
	for _, r := range rows {
		if n := len(d.Groups); n == 0 || d.Groups[n-1].Owner != r.Owner {
			d.Groups = append(d.Groups, repoGroup{Owner: r.Owner})
		}
		d.Groups[len(d.Groups)-1].Repos = append(d.Groups[len(d.Groups)-1].Repos, r)
		d.Attention = append(d.Attention, problems(r)...)
	}
	// Users sorted by name (the rows come sorted by path, so a user's
	// repositories are already together).
	slices.SortStableFunc(d.Groups, func(a, b repoGroup) int { return cmp.Compare(a.Owner, b.Owner) })
	for i := range d.Groups {
		var sum int64
		for _, r := range d.Groups[i].Repos {
			if !r.Missing {
				sum += r.Bytes
			}
		}
		d.Groups[i].Size = formatBytes(sum)
	}
	return d
}

// problems lists what needs attention for one repository.
func problems(r repoRow) []attention {
	view := "/repos/view?repo=" + url.QueryEscape(r.Path)
	if r.Missing {
		return []attention{{Path: r.Path, Problem: "no longer found below the repository root", Forget: true}}
	}
	var out []attention
	ownerKey := r.OwnerKey && !r.Password
	if !r.Password && !r.OwnerKey {
		out = append(out, attention{Path: r.Path, Problem: "no password stored: nothing can run", Action: "Set password", Link: "/repos/password?repo=" + url.QueryEscape(r.Path)})
	}
	if j := r.LastJob; j != nil && !j.OK && !j.Active {
		out = append(out, attention{Path: r.Path, Problem: j.Type + " " + j.State + " " + j.When, Action: "Show log", Link: "/jobs/" + strconv.FormatInt(j.ID, 10) + "/log"})
	}
	if r.LockError {
		out = append(out, attention{Path: r.Path, Problem: "lock files cannot be read"})
	} else if r.StaleLock && ownerKey {
		out = append(out, attention{Path: r.Path, Problem: "lock older than 24 h: probably stale; unlocking needs the password, ask the owner"})
	} else if r.StaleLock {
		out = append(out, attention{Path: r.Path, Problem: "lock older than 24 h: probably stale", Action: "Unlock", Link: view + "&tab=run"})
	}
	if r.StaleBackup && ownerKey {
		out = append(out, attention{Path: r.Path, Problem: "no new snapshot (last one " + r.LastBackup + "): ask the owner whether they still need it or need help", Action: "Mark as archive?", Link: view})
	} else if r.StaleBackup {
		out = append(out, attention{Path: r.Path, Problem: "no recent backup (last one " + r.LastBackup + ")", Action: "Mark as archive?", Link: view})
	}
	return out
}

// humanAge says how long ago t was, coarser the older it is: "5 min ago",
// "7 h ago", "3 days ago", "5 weeks ago", then the month ("Feb 2019").
func humanAge(now, t time.Time, loc *time.Location) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	case d < 14*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	case d < 8*7*24*time.Hour:
		return fmt.Sprintf("%d weeks ago", int(d.Hours()/24/7))
	}
	return t.In(loc).Format("Jan 2006")
}
