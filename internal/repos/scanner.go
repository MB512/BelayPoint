package repos

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Store is where the scanner records what it found (implemented by
// *store.Store).
type Store interface {
	SyncRepos(ctx context.Context, paths []string) error
	SetRepoUsage(ctx context.Context, path string, u Usage, at time.Time) error
}

// Scanner runs discovery plus disk usage in the background, one scan at a
// time.
type Scanner struct {
	Root   string
	Store  Store
	Logger *slog.Logger
	Now    func() time.Time

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup
}

// Start begins a scan in a new goroutine unless one is running; it
// returns false in that case. ctx ends the scan early (shutdown).
func (s *Scanner) Start(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	// wg.Go starts a goroutine (a lightweight thread managed by the Go
	// runtime, comparable to Task.Run in C#) and lets Wait wait for it.
	s.wg.Go(func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		s.scan(ctx)
	})
	return true
}

// Wait blocks until a running scan has finished (used on shutdown, after
// cancelling the scan's context).
func (s *Scanner) Wait() { s.wg.Wait() }

// Running reports whether a scan is in progress.
func (s *Scanner) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Scanner) scan(ctx context.Context) {
	start := s.Now()
	found, skipped, err := Discover(ctx, s.Root)
	if err != nil {
		s.Logger.Error("repository scan", "err", err)
		return
	}
	for _, e := range skipped {
		s.Logger.Warn("repository scan: skipped unreadable directory", "err", e)
	}
	if err := s.Store.SyncRepos(ctx, found); err != nil {
		s.Logger.Error("repository scan", "err", err)
		return
	}
	s.Logger.Info("repository scan: discovery done", "repositories", len(found))
	for _, rel := range found {
		dir, err := Dir(s.Root, rel)
		if err != nil {
			s.Logger.Warn("repository scan", "repo", rel, "err", err)
			continue
		}
		u, err := DiskUsage(ctx, dir)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.Logger.Warn("repository scan", "repo", rel, "err", err)
			continue
		}
		if err := s.Store.SetRepoUsage(ctx, rel, u, s.Now()); err != nil {
			s.Logger.Error("repository scan", "repo", rel, "err", err)
		}
	}
	s.Logger.Info("repository scan: done", "took", s.Now().Sub(start).Round(time.Millisecond).String())
}
