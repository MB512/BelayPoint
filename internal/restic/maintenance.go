package restic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
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

// Forget runs the passes of the policy (exclusive lock each): first the
// tag rules, then the main policy. A readable summary goes to log. A failed
// pass stops; the passes before it have already removed their snapshots.
func (c *CLI) Forget(ctx context.Context, dir string, password []byte, p Policy, log io.Writer) ([]PassResult, error) {
	passes, err := c.passes(ctx, dir, password, p)
	if err != nil {
		return nil, err
	}
	var results []PassResult
	for _, pass := range passes {
		name := "main policy"
		if pass.Tag != "" {
			name = "tag " + pass.Tag
		}
		fmt.Fprintf(log, "forget pass %s: %s\n", name, strings.Join(pass.Args, " "))
		args := append(append([]string{"forget", "--json"}, c.lockArgs()...), pass.Args...)
		var out bytes.Buffer
		if err := c.run(ctx, dir, password, args, &out, log); err != nil {
			return results, err
		}
		groups, err := parseForget(out.Bytes())
		if err != nil {
			return results, err
		}
		for _, g := range groups {
			fmt.Fprintf(log, "  group host=%s paths=%v: %d kept, %d removed\n", g.Host, g.Paths, len(g.Keep), len(g.Remove))
			for _, s := range g.Remove {
				fmt.Fprintf(log, "    removed %s %s %v\n", s.ShortID, s.Time.Format("2006-01-02 15:04:05"), s.Tags)
			}
		}
		results = append(results, PassResult{Tag: pass.Tag, Groups: groups})
	}
	return results, nil
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

// ValidSubset checks a --read-data-subset value of the form "n/t": part n
// of t, 1 <= n <= t <= MaxSubsetT.
func ValidSubset(subset string) error {
	nStr, tStr, ok := strings.Cut(subset, "/")
	n, errN := strconv.Atoi(nStr)
	t, errT := strconv.Atoi(tStr)
	if !ok || errN != nil || errT != nil || n < 1 || n > t || t > MaxSubsetT {
		return fmt.Errorf("invalid data subset %q: want n/t with 1 <= n <= t <= %d", subset, MaxSubsetT)
	}
	return nil
}

// MaxSubsetT bounds t in a "n/t" data subset (one part per day for a year).
const MaxSubsetT = 365

// Check verifies the repository structure; with subset (e.g. "2/7") it
// also reads that part of the data. Output goes to log.
func (c *CLI) Check(ctx context.Context, dir string, password []byte, subset string, log io.Writer) error {
	if subset != "" {
		if err := ValidSubset(subset); err != nil {
			return err
		}
	}
	args := append([]string{"check"}, c.lockArgs()...)
	if subset != "" {
		args = append(args, "--read-data-subset", subset)
	}
	return c.run(ctx, dir, password, args, log, log)
}
