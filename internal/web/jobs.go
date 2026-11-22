package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MB512/belaypoint/internal/jobs"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// Jobs queues restic jobs (implemented by *jobs.Manager).
type Jobs interface {
	Submit(ctx context.Context, repo string, typ jobs.Type, trigger jobs.Trigger) (int64, error)
	Busy(repo string) bool
}

// JobList reads the job history (implemented by *store.Store).
type JobList interface {
	ListJobs(ctx context.Context, limit int, before int64) ([]store.Job, error)
}

const jobsPageSize = 100

type jobRow struct {
	ID       int64
	Repo     string
	Type     string
	Trigger  string
	State    string
	Queued   string
	Duration string
	Summary  string
	Error    string
}

func (s *server) jobsPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	list, err := s.JobList.ListJobs(r.Context(), jobsPageSize, before)
	if err != nil {
		s.Logger.Error("listing jobs", "err", err)
		http.Error(w, "listing jobs failed; see the container log", http.StatusInternalServerError)
		return
	}
	p := page{Title: "Jobs", CSRF: sessionFrom(r.Context()).CSRF}
	for _, j := range list {
		row := jobRow{
			ID: j.ID, Repo: j.Repo, Type: j.Type, Trigger: j.Trigger, State: j.State,
			Queued: j.Queued.In(s.Location).Format("2006-01-02 15:04:05"), Summary: j.Summary, Error: j.Error,
		}
		if !j.Started.IsZero() && !j.Finished.IsZero() {
			row.Duration = j.Finished.Sub(j.Started).Round(time.Second).String()
		}
		p.Jobs = append(p.Jobs, row)
	}
	if len(list) == jobsPageSize {
		p.NextBefore = list[len(list)-1].ID
	}
	s.render(w, http.StatusOK, "jobs.html", p)
}

// refreshSnapshots queues a snapshots job for one repository (field repo)
// or, without it, for every present repository with a stored password that
// has no job yet.
func (s *server) refreshSnapshots(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	if s.Jobs == nil {
		s.renderHome(w, r, http.StatusServiceUnavailable, "restic is not available; see the container log.")
		return
	}
	if path := f.get("repo"); path != "" {
		s.submitJob(w, r, path, jobs.Snapshots)
		return
	}
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		http.Error(w, "listing repositories failed; see the container log", http.StatusInternalServerError)
		return
	}
	n := 0
	for _, repo := range list {
		if repo.Missing || !s.Vault.Has(vault.RepoSecret(repo.Path)) || s.Jobs.Busy(repo.Path) {
			continue
		}
		if _, err := s.Jobs.Submit(r.Context(), repo.Path, jobs.Snapshots, jobs.Manual); err != nil {
			if errors.Is(err, jobs.ErrBusy) {
				continue
			}
			s.renderHome(w, r, jobErrorStatus(err), "Refreshing snapshots: "+err.Error())
			return
		}
		n++
	}
	s.Audit.Audit(r.Context(), "job submitted", fmt.Sprintf("snapshots, %d repositories, %s", n, remote(r)))
	redirect(w, r, "/")
}

// submitJob queues one job for a known repository, audits it and returns
// to the overview (errors are shown there).
func (s *server) submitJob(w http.ResponseWriter, r *http.Request, path string, typ jobs.Type) {
	if s.Jobs == nil {
		s.renderHome(w, r, http.StatusServiceUnavailable, "restic is not available; see the container log.")
		return
	}
	if _, ok := s.knownRepo(r.Context(), path); !ok {
		http.NotFound(w, r)
		return
	}
	id, err := s.Jobs.Submit(r.Context(), path, typ, jobs.Manual)
	if err != nil {
		s.renderHome(w, r, jobErrorStatus(err), string(typ)+" for "+path+": "+err.Error())
		return
	}
	s.Audit.Audit(r.Context(), "job submitted", fmt.Sprintf("%s, %s, job %d, %s", typ, path, id, remote(r)))
	redirect(w, r, "/")
}

// unlock removes stale locks (restic decides what is stale).
func (s *server) unlock(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	s.submitJob(w, r, f.get("repo"), jobs.Unlock)
}

func (s *server) unlockAllPage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("repo")
	if _, ok := s.knownRepo(r.Context(), path); !ok {
		http.NotFound(w, r)
		return
	}
	s.renderUnlockAll(w, r, http.StatusOK, path, "")
}

func (s *server) renderUnlockAll(w http.ResponseWriter, r *http.Request, status int, path, errMsg string) {
	s.render(w, status, "unlock-all.html", page{
		Title: "Remove all locks", CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg,
		RepoPassword: &repoPasswordData{Path: path},
	})
}

// unlockAll runs "unlock --remove-all". It can break a running backup, so
// the repository name must be typed (CLAUDE.md, hard rules).
func (s *server) unlockAll(w http.ResponseWriter, r *http.Request) {
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
	if f.get("confirm_name") != path {
		s.renderUnlockAll(w, r, http.StatusBadRequest, path, "The typed name does not match the repository.")
		return
	}
	s.submitJob(w, r, path, jobs.UnlockAll)
}

// jobLog shows the log file of a job (the last maxLogBytes of it).
func (s *server) jobLog(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 || s.JobLogDir == "" {
		http.NotFound(w, r)
		return
	}
	text, truncated, err := readTail(jobs.LogPath(s.JobLogDir, id), maxLogBytes)
	if errors.Is(err, fs.ErrNotExist) {
		text = "(no log: the job did not start, or its log was removed after the retention period)"
	} else if err != nil {
		s.Logger.Error("reading job log", "job", id, "err", err)
		http.Error(w, "reading the log failed; see the container log", http.StatusInternalServerError)
		return
	}
	s.render(w, http.StatusOK, "job-log.html", page{
		Title: fmt.Sprintf("Job %d", id), CSRF: sessionFrom(r.Context()).CSRF,
		Log: &logData{Text: text, Truncated: truncated},
	})
}

const maxLogBytes = 1 << 20

type logData struct {
	Text      string
	Truncated bool
}

// readTail reads at most limit bytes from the end of the file.
func readTail(path string, limit int64) (string, bool, error) {
	f, err := os.Open(path) //nolint:gosec // path is jobs.LogPath(JobLogDir, <parsed int>)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	off := max(st.Size()-limit, 0)
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	return string(buf), off > 0, nil
}

func jobErrorStatus(err error) int {
	switch {
	case errors.Is(err, jobs.ErrBusy), errors.Is(err, jobs.ErrQueueFull):
		return http.StatusConflict
	case errors.Is(err, jobs.ErrNoPassword):
		return http.StatusBadRequest
	case errors.Is(err, jobs.ErrSealed), errors.Is(err, jobs.ErrStopped):
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}
