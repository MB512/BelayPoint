package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID      int64
	Time    time.Time
	Event   string
	Details string
}

// AddAudit appends an entry. details must not contain secrets.
func (s *Store) AddAudit(ctx context.Context, event, details string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (time, event, details) VALUES (?, ?, ?)`,
		s.now().UnixMilli(), event, details)
	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

// ListAudit returns up to limit entries, newest first, with an ID below
// before (0 = from the newest). Pass the last ID of a page as before to
// get the next page.
func (s *Store) ListAudit(ctx context.Context, limit int, before int64) ([]AuditEntry, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, time, event, details FROM audit WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ms int64
		if err := rows.Scan(&e.ID, &ms, &e.Event, &e.Details); err != nil {
			return nil, fmt.Errorf("reading audit log: %w", err)
		}
		e.Time = time.UnixMilli(ms)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}
	return out, nil
}
