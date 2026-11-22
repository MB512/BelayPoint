package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Policy is a retention policy for "restic forget". Snapshots are grouped
// by host and paths (GroupBy), so every client and backup set keeps its
// own history. Zero values are left out.
type Policy struct {
	KeepLast    int `json:"keep_last,omitempty"`
	KeepHourly  int `json:"keep_hourly,omitempty"`
	KeepDaily   int `json:"keep_daily,omitempty"`
	KeepWeekly  int `json:"keep_weekly,omitempty"`
	KeepMonthly int `json:"keep_monthly,omitempty"`
	KeepYearly  int `json:"keep_yearly,omitempty"`
	// KeepWithin keeps all snapshots younger than this restic duration,
	// e.g. "14d" or "1y6m".
	KeepWithin string `json:"keep_within,omitempty"`
}

// DefaultPolicy applies to repositories without their own policy.
var DefaultPolicy = Policy{KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12, KeepYearly: 3}

// GroupBy is passed as --group-by.
const GroupBy = "host,paths"

// MaxKeep bounds each count; it only guards against typos.
const MaxKeep = 100000

// ErrPolicy is returned by Policy.Validate.
var ErrPolicy = errors.New("invalid retention policy")

var resticDuration = regexp.MustCompile(`^([0-9]{1,5}[ymdh])+$`)

// Validate checks the policy. An empty policy is refused: restic would
// keep everything, which is never what a scheduled forget is meant to do.
func (p Policy) Validate() error {
	for name, n := range map[string]int{
		"keep last": p.KeepLast, "keep hourly": p.KeepHourly, "keep daily": p.KeepDaily,
		"keep weekly": p.KeepWeekly, "keep monthly": p.KeepMonthly, "keep yearly": p.KeepYearly,
	} {
		if n < 0 || n > MaxKeep {
			return fmt.Errorf("%w: %s must be between 0 and %d", ErrPolicy, name, MaxKeep)
		}
	}
	if p.KeepWithin != "" && !resticDuration.MatchString(p.KeepWithin) {
		return fmt.Errorf("%w: keep within must look like 14d, 6m or 1y6m (y, m, d, h)", ErrPolicy)
	}
	if p == (Policy{}) {
		return fmt.Errorf("%w: at least one keep rule is needed", ErrPolicy)
	}
	return nil
}

// Args returns the restic arguments of the policy. Every value is a
// separate argument; nothing is passed through a shell.
func (p Policy) Args() []string {
	args := []string{"--group-by", GroupBy}
	add := func(flag string, n int) {
		if n > 0 {
			args = append(args, flag, strconv.Itoa(n))
		}
	}
	add("--keep-last", p.KeepLast)
	add("--keep-hourly", p.KeepHourly)
	add("--keep-daily", p.KeepDaily)
	add("--keep-weekly", p.KeepWeekly)
	add("--keep-monthly", p.KeepMonthly)
	add("--keep-yearly", p.KeepYearly)
	if p.KeepWithin != "" {
		args = append(args, "--keep-within", p.KeepWithin)
	}
	return args
}

// ForgetGroup is one group of "restic forget --json": the snapshots of one
// host and set of paths, split into kept and removed.
type ForgetGroup struct {
	Host   string     `json:"host"`
	Paths  []string   `json:"paths"`
	Keep   []Snapshot `json:"keep"`
	Remove []Snapshot `json:"remove"`
}

// ForgetPreview runs "forget --dry-run --no-lock": it shows what the policy
// would remove and changes nothing (without --no-lock even a dry run takes
// an exclusive lock).
func (c *CLI) ForgetPreview(ctx context.Context, dir string, password []byte, p Policy) ([]ForgetGroup, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	args := append([]string{"forget", "--dry-run", "--no-lock", "--json"}, p.Args()...)
	var out bytes.Buffer
	if err := c.run(ctx, dir, password, args, &out, nil); err != nil {
		return nil, err
	}
	return parseForget(out.Bytes())
}

func parseForget(data []byte) ([]ForgetGroup, error) {
	var groups []ForgetGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("parsing restic forget output: %w", err)
	}
	return groups, nil
}
