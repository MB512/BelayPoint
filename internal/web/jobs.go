package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
		if _, ok := s.knownRepo(r.Context(), path); !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := s.Jobs.Submit(r.Context(), path, jobs.Snapshots, jobs.Manual); err != nil {
			s.renderHome(w, r, jobErrorStatus(err), "Refreshing snapshots of "+path+": "+err.Error())
			return
		}
		s.Audit.Audit(r.Context(), "job submitted", "snapshots, "+path+", "+remote(r))
		redirect(w, r, "/")
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
