package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Job is a row of the jobs table.
type Job struct {
	ID       int64
	Repo     string
	Type     string
	Trigger  string
	State    string
	Queued   time.Time
	Started  time.Time // zero if not started
	Finished time.Time // zero if not finished
	Summary  string
	Error    string
}

// AddJob records a queued job and returns its id.
func (s *Store) AddJob(ctx context.Context, repo, typ, trigger string, queued time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (repo, type, trigger, state, queued) VALUES (?, ?, ?, 'queued', ?)`,
		repo, typ, trigger, queued.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("adding job: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("adding job: %w", err)
	}
	return id, nil
}

// StartJob marks a job running.
func (s *Store) StartJob(ctx context.Context, id int64, at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET state = 'running', started = ? WHERE id = ?`, at.UnixMilli(), id); err != nil {
		return fmt.Errorf("starting job %d: %w", id, err)
	}
	return nil
}

// FinishJob records the end state of a job.
func (s *Store) FinishJob(ctx context.Context, id int64, state, summary, errText string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET state = ?, summary = ?, error = ?, finished = ? WHERE id = ?`,
		state, summary, errText, at.UnixMilli(), id); err != nil {
		return fmt.Errorf("finishing job %d: %w", id, err)
	}
	return nil
}

// InterruptJobs marks jobs left queued or running by a previous process
// as interrupted and returns how many there were.
func (s *Store) InterruptJobs(ctx context.Context, at time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET state = 'interrupted', finished = ? WHERE state IN ('queued', 'running')`, at.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("interrupting jobs: %w", err)
	}
	return res.RowsAffected()
}

// ListJobs returns up to limit jobs, newest first, with an id below before
// (0: from the newest).
func (s *Store) ListJobs(ctx context.Context, limit int, before int64) ([]Job, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, repo, type, trigger, state, queued, started, finished, summary, error
		 FROM jobs WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Job
	for rows.Next() {
		var j Job
		var queued int64
		var started, finished sql.NullInt64
		if err := rows.Scan(&j.ID, &j.Repo, &j.Type, &j.Trigger, &j.State, &queued, &started, &finished, &j.Summary, &j.Error); err != nil {
			return nil, fmt.Errorf("listing jobs: %w", err)
		}
		j.Queued = time.UnixMilli(queued)
		if started.Valid {
			j.Started = time.UnixMilli(started.Int64)
		}
		if finished.Valid {
			j.Finished = time.UnixMilli(finished.Int64)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	return out, nil
}

// SetRepoSnapshots stores the snapshot summary of a repository; newest is
// the zero time when there are no snapshots.
func (s *Store) SetRepoSnapshots(ctx context.Context, path string, count int, newest, at time.Time) error {
	var n sql.NullInt64
	if !newest.IsZero() {
		n = sql.NullInt64{Int64: newest.UnixMilli(), Valid: true}
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE repos SET snapshot_count = ?, snapshot_newest = ?, snapshots_time = ? WHERE path = ?`,
		count, n, at.UnixMilli(), path); err != nil {
		return fmt.Errorf("storing snapshots of %q: %w", path, err)
	}
	return nil
}
