// Package store is BelayPoint's SQLite database (see "Data model" in
// docs/architecture.md). It holds no secrets.
//
// The schema is created and upgraded by numbered SQL files in migrations/,
// embedded into the binary. Each file runs once, in its own transaction;
// the number of the last one applied is kept in the meta table.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no CGO)
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store wraps the database. Safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at file and applies
// pending migrations. A database with a newer schema than this binary
// knows is refused, so a downgrade cannot damage it.
func Open(ctx context.Context, file string) (*Store, error) {
	return open(ctx, file, migrationFS, time.Now)
}

func open(ctx context.Context, file string, migrations fs.FS, now func() time.Time) (*Store, error) {
	// WAL lets readers run while a write is in progress; busy_timeout
	// waits for a lock instead of failing at once.
	dsn := "file:" + file + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// One connection: SQLite allows one writer anyway, and the load here
	// is tiny. This avoids SQLITE_BUSY between our own connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: now}
	if err := s.migrate(ctx, migrations); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for i, name := range names { // fs.Glob returns sorted names
		base := path.Base(name)
		num, _, ok := strings.Cut(base, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v != i+1 {
			return nil, fmt.Errorf("migration %s: want number %04d", base, i+1)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: base, sql: string(data)})
	}
	return ms, nil
}

func (s *Store) migrate(ctx context.Context, fsys fs.FS) error {
	ms, err := loadMigrations(fsys)
	if err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("creating meta table: %w", err)
	}
	current, err := s.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if current > len(ms) {
		return fmt.Errorf("database schema version %d is newer than this BelayPoint (%d); use a newer image", current, len(ms))
	}
	for _, m := range ms[current:] {
		if err := s.apply(ctx, m); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *Store) schemaVersion(ctx context.Context) (int, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("schema version %q: %w", v, err)
	}
	return n, nil
}

func (s *Store) apply(ctx context.Context, m migration) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Roll back unless committed; Rollback after Commit is a no-op.
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, strconv.Itoa(m.version)); err != nil {
		return err
	}
	return tx.Commit()
}
