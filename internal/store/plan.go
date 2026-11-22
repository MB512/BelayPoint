package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Plan is the maintenance plan of a repository.
type Plan struct {
	Enabled  bool
	Schedule string // cron expression, validated by internal/scheduler
	Unlock   bool
	Forget   bool
	Prune    bool
	Check    bool
	// CheckSubsetT is the number of runs over which check reads all data
	// once (--read-data-subset n/t); 0 reads no data.
	CheckSubsetT int
	// CheckSubsetN is the subset the next check reads (1..T).
	CheckSubsetN int
}

// MaxCheckSubsetT bounds the rotation.
const MaxCheckSubsetT = 365

const planColumns = `plan_enabled, plan_schedule, plan_unlock, plan_forget, plan_prune, plan_check, check_subset_n, check_subset_t`

func scanPlan(row interface{ Scan(...any) error }, p *Plan, extra ...any) error {
	return row.Scan(append(extra, &p.Enabled, &p.Schedule, &p.Unlock, &p.Forget, &p.Prune, &p.Check, &p.CheckSubsetN, &p.CheckSubsetT)...)
}

// RepoPlan returns the plan of a repository.
func (s *Store) RepoPlan(ctx context.Context, path string) (Plan, error) {
	var p Plan
	err := scanPlan(s.db.QueryRowContext(ctx, `SELECT `+planColumns+` FROM repos WHERE path = ?`, path), &p)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, fmt.Errorf("plan of %q: %w", path, ErrNotFound)
	}
	if err != nil {
		return Plan{}, fmt.Errorf("plan of %q: %w", path, err)
	}
	return p, nil
}

// SetRepoPlan stores a plan; the schedule must be validated by the caller.
// The subset position is kept, but moved back into 1..T if T shrank.
func (s *Store) SetRepoPlan(ctx context.Context, path string, p Plan) error {
	if p.CheckSubsetT < 0 || p.CheckSubsetT > MaxCheckSubsetT {
		return fmt.Errorf("check rotation must be between 0 and %d runs", MaxCheckSubsetT)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE repos SET plan_enabled = ?, plan_schedule = ?, plan_unlock = ?, plan_forget = ?, plan_prune = ?,
		        plan_check = ?, check_subset_t = ?,
		        check_subset_n = CASE WHEN check_subset_n > ? OR check_subset_n < 1 THEN 1 ELSE check_subset_n END
		 WHERE path = ?`,
		p.Enabled, p.Schedule, p.Unlock, p.Forget, p.Prune, p.Check, p.CheckSubsetT, max(p.CheckSubsetT, 1), path)
	if err != nil {
		return fmt.Errorf("storing plan of %q: %w", path, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("plan of %q: %w", path, ErrNotFound)
	}
	return nil
}

// AdvanceCheckSubset moves the rotation to the next subset after a
// successful check (T wraps to 1).
func (s *Store) AdvanceCheckSubset(ctx context.Context, path string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE repos SET check_subset_n = CASE WHEN check_subset_n >= check_subset_t THEN 1 ELSE check_subset_n + 1 END
		 WHERE path = ?`, path); err != nil {
		return fmt.Errorf("advancing check subset of %q: %w", path, err)
	}
	return nil
}

// ScheduledRepo is a present repository with an enabled plan.
type ScheduledRepo struct {
	Path string
	Plan Plan
}

// ScheduledRepos lists present repositories with an enabled plan.
func (s *Store) ScheduledRepos(ctx context.Context) ([]ScheduledRepo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT path, `+planColumns+` FROM repos WHERE plan_enabled = 1 AND missing = 0 ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("listing plans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ScheduledRepo
	for rows.Next() {
		var r ScheduledRepo
		if err := scanPlan(rows, &r.Plan, &r.Path); err != nil {
			return nil, fmt.Errorf("listing plans: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing plans: %w", err)
	}
	return out, nil
}

// AddSkippedJob records a scheduled run that did not start (sealed, no
// password, still busy) with the reason.
func (s *Store) AddSkippedJob(ctx context.Context, repo, typ, trigger, reason string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (repo, type, trigger, state, queued, finished, error) VALUES (?, ?, ?, 'skipped', ?, ?, ?)`,
		repo, typ, trigger, at.UnixMilli(), at.UnixMilli(), reason); err != nil {
		return fmt.Errorf("recording skipped job: %w", err)
	}
	return nil
}
