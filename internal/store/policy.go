package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MB512/belaypoint/internal/restic"
)

// ErrNotFound is returned for an unknown repository.
var ErrNotFound = errors.New("not found")

// RepoPolicy returns the retention policy of a repository; custom is false
// when the default applies.
func (s *Store) RepoPolicy(ctx context.Context, path string) (p restic.Policy, custom bool, err error) {
	var raw sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT policy FROM repos WHERE path = ?`, path).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return restic.Policy{}, false, fmt.Errorf("policy of %q: %w", path, ErrNotFound)
	}
	if err != nil {
		return restic.Policy{}, false, fmt.Errorf("policy of %q: %w", path, err)
	}
	if !raw.Valid {
		return restic.DefaultPolicy, false, nil
	}
	if err := json.Unmarshal([]byte(raw.String), &p); err != nil {
		return restic.Policy{}, false, fmt.Errorf("policy of %q: %w", path, err)
	}
	return p, true, nil
}

// SetRepoPolicy stores a validated policy; nil resets to the default.
func (s *Store) SetRepoPolicy(ctx context.Context, path string, p *restic.Policy) error {
	var raw sql.NullString
	if p != nil {
		if err := p.Validate(); err != nil {
			return err
		}
		b, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("policy of %q: %w", path, err)
		}
		raw = sql.NullString{String: string(b), Valid: true}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE repos SET policy = ? WHERE path = ?`, raw, path)
	if err != nil {
		return fmt.Errorf("storing policy of %q: %w", path, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("policy of %q: %w", path, ErrNotFound)
	}
	return nil
}
