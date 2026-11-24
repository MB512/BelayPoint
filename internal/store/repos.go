package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
)

// Repo is a row of the repos table.
type Repo struct {
	Path      string
	Missing   bool
	FirstSeen time.Time
	LastSeen  time.Time
	// Usage is nil until the first disk usage walk finished.
	Usage     *repos.Usage
	UsageTime time.Time
	// Snapshots is nil until the first snapshots job succeeded.
	Snapshots *SnapshotSummary
	// Archived: closed repository, no new backups expected.
	Archived bool
}

// SnapshotSummary is the cached result of the last snapshot listing.
type SnapshotSummary struct {
	Count  int
	Newest time.Time // zero if there are none
	Time   time.Time // when they were listed
}

// SyncRepos records the result of a discovery: paths are present (added
// if new), every other known repository is marked missing.
func (s *Store) SyncRepos(ctx context.Context, paths []string) error {
	now := s.now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("syncing repositories: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE repos SET missing = 1`); err != nil {
		return fmt.Errorf("syncing repositories: %w", err)
	}
	for _, p := range paths {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO repos (path, missing, first_seen, last_seen) VALUES (?, 0, ?, ?)
			 ON CONFLICT (path) DO UPDATE SET missing = 0, last_seen = excluded.last_seen`, p, now, now); err != nil {
			return fmt.Errorf("syncing repository %q: %w", p, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("syncing repositories: %w", err)
	}
	return nil
}

// SetRepoUsage stores a disk usage measurement.
func (s *Store) SetRepoUsage(ctx context.Context, path string, u repos.Usage, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE repos SET usage_bytes = ?, usage_files = ?, usage_time = ? WHERE path = ?`,
		u.Bytes, u.Files, at.UnixMilli(), path)
	if err != nil {
		return fmt.Errorf("storing disk usage of %q: %w", path, err)
	}
	return nil
}

// ListRepos returns all known repositories, sorted by path.
func (s *Store) ListRepos(ctx context.Context) ([]Repo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT path, missing, first_seen, last_seen, usage_bytes, usage_files, usage_time,
		        snapshot_count, snapshot_newest, snapshots_time, archived
		 FROM repos ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Repo
	for rows.Next() {
		var r Repo
		var first, last int64
		// sql.Null* are like Nullable<T> in C#: Valid says whether the
		// column was NULL.
		var bytes, files, at, count, newest, listed sql.NullInt64
		if err := rows.Scan(&r.Path, &r.Missing, &first, &last, &bytes, &files, &at, &count, &newest, &listed, &r.Archived); err != nil {
			return nil, fmt.Errorf("listing repositories: %w", err)
		}
		r.FirstSeen, r.LastSeen = time.UnixMilli(first), time.UnixMilli(last)
		if bytes.Valid {
			r.Usage = &repos.Usage{Bytes: bytes.Int64, Files: files.Int64}
			r.UsageTime = time.UnixMilli(at.Int64)
		}
		if count.Valid {
			r.Snapshots = &SnapshotSummary{Count: int(count.Int64), Time: time.UnixMilli(listed.Int64)}
			if newest.Valid {
				r.Snapshots.Newest = time.UnixMilli(newest.Int64)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing repositories: %w", err)
	}
	return out, nil
}

// RepoArchived reports whether the repository is marked as an archive.
func (s *Store) RepoArchived(ctx context.Context, path string) (bool, error) {
	var archived bool
	err := s.db.QueryRowContext(ctx, `SELECT archived FROM repos WHERE path = ?`, path).Scan(&archived)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("repository %q: %w", path, ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("reading archive flag of %q: %w", path, err)
	}
	return archived, nil
}

// SetRepoArchived marks the repository as an archive or as active.
func (s *Store) SetRepoArchived(ctx context.Context, path string, archived bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE repos SET archived = ? WHERE path = ?`, archived, path)
	if err != nil {
		return fmt.Errorf("storing archive flag of %q: %w", path, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("repository %q: %w", path, ErrNotFound)
	}
	return nil
}
