package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Setting returns a stored setting; ok is false if it was never set.
func (s *Store) Setting(ctx context.Context, key string) (value string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading setting %q: %w", key, err)
	}
	return value, true, nil
}

// SetSetting stores a setting (insert or replace).
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("storing setting %q: %w", key, err)
	}
	return nil
}
