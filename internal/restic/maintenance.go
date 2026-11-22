package restic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
)

// DefaultMaxUnused is passed to prune as --max-unused: up to this share of
// unused data may stay in the repository, so prune rewrites fewer packs.
const DefaultMaxUnused = "5%"

var maxUnused = regexp.MustCompile(`^([0-9]{1,2}(\.[0-9]+)?%|100%|unlimited)$`)

// lockArgs makes restic wait for other locks instead of failing at once
// (issue #2).
func (c *CLI) lockArgs() []string {
	if c.RetryLock <= 0 {
		return nil
	}
	return []string{"--retry-lock", c.RetryLock.String()}
}

// Forget removes the snapshots the policy does not keep (exclusive lock).
// A readable summary goes to log; it returns restic's groups (kept and
// removed snapshots).
func (c *CLI) Forget(ctx context.Context, dir string, password []byte, p Policy, log io.Writer) ([]ForgetGroup, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	args := append(append([]string{"forget", "--json"}, c.lockArgs()...), p.Args()...)
	var out bytes.Buffer
	if err := c.run(ctx, dir, password, args, &out, log); err != nil {
		return nil, err
	}
	groups, err := parseForget(out.Bytes())
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		fmt.Fprintf(log, "group host=%s paths=%v: %d kept, %d removed\n", g.Host, g.Paths, len(g.Keep), len(g.Remove))
		for _, s := range g.Remove {
			fmt.Fprintf(log, "  removed %s %s\n", s.ShortID, s.Time.Format("2006-01-02 15:04:05"))
		}
	}
	return groups, nil
}

// Prune removes data no snapshot references (exclusive lock). restic's
// text output goes to log.
func (c *CLI) Prune(ctx context.Context, dir string, password []byte, unused string, log io.Writer) error {
	if !maxUnused.MatchString(unused) {
		return fmt.Errorf("invalid --max-unused %q", unused)
	}
	args := append([]string{"prune", "--max-unused", unused}, c.lockArgs()...)
	return c.run(ctx, dir, password, args, log, log)
}

// Check verifies the repository structure; with subset (e.g. "2/7") it
// also reads that part of the data. Output goes to log.
func (c *CLI) Check(ctx context.Context, dir string, password []byte, subset string, log io.Writer) error {
	args := append([]string{"check"}, c.lockArgs()...)
	if subset != "" {
		args = append(args, "--read-data-subset", subset)
	}
	return c.run(ctx, dir, password, args, log, log)
}
