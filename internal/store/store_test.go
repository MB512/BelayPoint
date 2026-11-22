package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "belaypoint.db")
	s, err := Open(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, file
}

func TestMigrationsApplyOnceAndPersist(t *testing.T) {
	ctx := context.Background()
	s, file := openTest(t)
	if err := s.AddAudit(ctx, "login", "from 192.168.1.20:5000"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// Reopening runs no migration again (it would fail: table exists).
	s2, err := Open(ctx, file)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	v, err := s2.schemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := loadMigrations(migrationFS)
	if v != len(ms) {
		t.Errorf("schema version %d, want %d", v, len(ms))
	}
	got, err := s2.ListAudit(ctx, 10, 0)
	if err != nil || len(got) != 1 || got[0].Event != "login" {
		t.Errorf("after reopen: %v, %v", got, err)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	ctx := context.Background()
	s, file := openTest(t)
	if _, err := s.db.ExecContext(ctx, `UPDATE meta SET value = '999' WHERE key = 'schema_version'`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(ctx, file); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("Open with newer schema: %v", err)
	}
}

func TestMigrationFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "db")
	fsys := fstest.MapFS{
		"migrations/0001_ok.sql":  {Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"migrations/0002_bad.sql": {Data: []byte(`CREATE TABLE b (x INTEGER); THIS IS NOT SQL;`)},
	}
	if _, err := open(ctx, file, fsys, time.Now); err == nil {
		t.Fatal("bad migration succeeded")
	}
	delete(fsys, "migrations/0002_bad.sql")
	s, err := open(ctx, file, fsys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if v, _ := s.schemaVersion(ctx); v != 1 {
		t.Errorf("schema version %d, want 1", v)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name = 'b'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("table b exists after failed migration (n=%d, err=%v)", n, err)
	}
}

func TestMigrationNumbering(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		ok    bool
	}{
		{"sequential", []string{"0001_a.sql", "0002_b.sql"}, true},
		{"gap", []string{"0001_a.sql", "0003_b.sql"}, false},
		{"no number", []string{"init.sql"}, false},
		{"starts at 2", []string{"0002_a.sql"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for _, f := range tt.files {
				fsys["migrations/"+f] = &fstest.MapFile{Data: []byte("SELECT 1;")}
			}
			_, err := loadMigrations(fsys)
			if (err == nil) != tt.ok {
				t.Errorf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestAuditPaging(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		s.now = func() time.Time { return base.Add(time.Duration(i) * time.Minute) }
		if err := s.AddAudit(ctx, "event", string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := s.ListAudit(ctx, 3, 0)
	if err != nil || len(page1) != 3 {
		t.Fatalf("page 1: %v %v", page1, err)
	}
	if page1[0].Details != "e" || page1[2].Details != "c" {
		t.Errorf("page 1 order: %v", page1)
	}
	if !page1[0].Time.Equal(base.Add(4 * time.Minute)) {
		t.Errorf("time %v", page1[0].Time)
	}
	page2, err := s.ListAudit(ctx, 3, page1[2].ID)
	if err != nil || len(page2) != 2 || page2[0].Details != "b" || page2[1].Details != "a" {
		t.Errorf("page 2: %v %v", page2, err)
	}
}
