package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Keep holds the keep rules of "restic forget". Zero values are left out.
type Keep struct {
	KeepLast    int `json:"keep_last,omitempty"`
	KeepHourly  int `json:"keep_hourly,omitempty"`
	KeepDaily   int `json:"keep_daily,omitempty"`
	KeepWeekly  int `json:"keep_weekly,omitempty"`
	KeepMonthly int `json:"keep_monthly,omitempty"`
	KeepYearly  int `json:"keep_yearly,omitempty"`
	// KeepWithin keeps all snapshots younger than this restic duration
	// (relative to the newest snapshot of the group), e.g. "14d", "1y6m".
	KeepWithin string `json:"keep_within,omitempty"`
}

// TagRule is a separate retention for the snapshots with one tag, e.g.
// StackBelay's "pre-stop" snapshots.
type TagRule struct {
	Tag string `json:"tag"`
	Keep
}

// Policy is a retention policy. Snapshots are grouped by host and paths
// (GroupBy), so every client and backup set keeps its own history.
//
// forget runs one pass per tag rule ("forget --tag <tag>" with the rule's
// keep values), then the main pass with Keep over the snapshots without a
// rule tag only. restic has no "without tag" filter, and --keep-tag would
// still let protected snapshots take keep slots, so the main pass selects
// the tag combinations found in the repository that contain no rule tag
// (see Passes).
//
// Keep is embedded: its fields are accessed as p.KeepDaily, like members
// inherited from a base class in C# (embedding is composition, though).
type Policy struct {
	Keep
	TagRules []TagRule `json:"tag_rules,omitempty"`
}

// TagPreStop is the tag of StackBelay's pre-stop snapshots: taken while the
// stack still runs, so not consistent; the final snapshot follows.
const TagPreStop = "pre-stop"

// DefaultPolicy applies to repositories without their own policy. Its tag
// rule removes nothing in repositories without pre-stop snapshots.
var DefaultPolicy = Policy{
	Keep:     Keep{KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 12, KeepYearly: 3},
	TagRules: []TagRule{{Tag: TagPreStop, Keep: Keep{KeepLast: 2}}},
}

// GroupBy is passed as --group-by.
const GroupBy = "host,paths"

// Limits that only guard against typos and abuse.
const (
	MaxKeep     = 100000
	MaxTagRules = 5
)

// ErrPolicy is returned by Policy.Validate.
var ErrPolicy = errors.New("invalid retention policy")

var (
	resticDuration = regexp.MustCompile(`^([0-9]{1,5}[ymdh])+$`)
	// validTag excludes "," (restic reads it as a tag list) and anything
	// that could look like an option.
	validTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._:@+-]{0,63}$`)
)

// Empty reports whether no keep rule is set.
func (k Keep) Empty() bool { return k == Keep{} }

func (k Keep) validate(what string) error {
	for name, n := range map[string]int{
		"keep last": k.KeepLast, "keep hourly": k.KeepHourly, "keep daily": k.KeepDaily,
		"keep weekly": k.KeepWeekly, "keep monthly": k.KeepMonthly, "keep yearly": k.KeepYearly,
	} {
		if n < 0 || n > MaxKeep {
			return fmt.Errorf("%w: %s%s must be between 0 and %d", ErrPolicy, what, name, MaxKeep)
		}
	}
	if k.KeepWithin != "" && !resticDuration.MatchString(k.KeepWithin) {
		return fmt.Errorf("%w: %skeep within must look like 14d, 6m or 1y6m (y, m, d, h)", ErrPolicy, what)
	}
	// An empty rule would make restic keep everything (and do nothing).
	if k.Empty() {
		return fmt.Errorf("%w: %sat least one keep rule is needed", ErrPolicy, what)
	}
	return nil
}

// Args returns the keep rules as restic arguments, each value a separate
// argument (nothing goes through a shell).
func (k Keep) Args() []string {
	var args []string
	add := func(flag string, n int) {
		if n > 0 {
			args = append(args, flag, strconv.Itoa(n))
		}
	}
	add("--keep-last", k.KeepLast)
	add("--keep-hourly", k.KeepHourly)
	add("--keep-daily", k.KeepDaily)
	add("--keep-weekly", k.KeepWeekly)
	add("--keep-monthly", k.KeepMonthly)
	add("--keep-yearly", k.KeepYearly)
	if k.KeepWithin != "" {
		args = append(args, "--keep-within", k.KeepWithin)
	}
	return args
}

// String is a short description for logs and the audit log.
func (k Keep) String() string { return strings.Join(k.Args(), " ") }

// Validate checks the policy.
func (p Policy) Validate() error {
	if err := p.validate(""); err != nil {
		return err
	}
	if len(p.TagRules) > MaxTagRules {
		return fmt.Errorf("%w: at most %d tag rules", ErrPolicy, MaxTagRules)
	}
	seen := map[string]bool{}
	for _, r := range p.TagRules {
		if !validTag.MatchString(r.Tag) {
			return fmt.Errorf("%w: tag %q: letters, digits and . _ : @ + - only", ErrPolicy, r.Tag)
		}
		if seen[r.Tag] {
			return fmt.Errorf("%w: tag %q has two rules", ErrPolicy, r.Tag)
		}
		seen[r.Tag] = true
		if err := r.validate("tag " + r.Tag + ": "); err != nil {
			return err
		}
	}
	return nil
}

// String describes the whole policy, e.g.
// "--keep-daily 7 ...; tag pre-stop: --keep-last 2".
func (p Policy) String() string {
	s := p.Keep.String()
	for _, r := range p.TagRules {
		s += "; tag " + r.Tag + ": " + r.String() // Keep.String, promoted
	}
	return s
}

// Pass is one "restic forget" run of a policy.
type Pass struct {
	Tag  string   // "" for the main pass
	Args []string // forget arguments after "forget"
}

// ErrTagOverlap is returned when a snapshot with a rule tag would also be
// selected by the main pass.
var ErrTagOverlap = errors.New("snapshot tags overlap the tag rules")

// Passes returns the forget runs in order: one per tag rule, then the main
// pass. snapshots is the current list of the repository; it is needed only
// with tag rules, to restrict the main pass to the snapshots without a rule
// tag. If there are none, the main pass is left out.
func (p Policy) Passes(snapshots []Snapshot) ([]Pass, error) {
	base := []string{"--group-by", GroupBy}
	if len(p.TagRules) == 0 {
		return []Pass{{Args: append(base, p.Args()...)}}, nil
	}
	var passes []Pass
	ruleTag := map[string]bool{}
	for _, r := range p.TagRules {
		ruleTag[r.Tag] = true
		args := append(append(slices.Clone(base), "--tag", r.Tag), r.Args()...)
		passes = append(passes, Pass{Tag: r.Tag, Args: args})
	}
	// The distinct tag sets of the snapshots without a rule tag. "--tag a,b"
	// selects snapshots that have a and b (and maybe more); "--tag ''"
	// selects untagged ones; several --tag options are alternatives.
	filters := map[string][]string{}
	for _, s := range snapshots {
		if slices.ContainsFunc(s.Tags, func(t string) bool { return ruleTag[t] }) {
			continue
		}
		tags := slices.Sorted(slices.Values(s.Tags))
		filters[strings.Join(tags, ",")] = tags
	}
	// A snapshot with a rule tag must not match any of these filters (it
	// would match when it has all tags of a filter, e.g. "final,pre-stop"
	// matches "--tag final").
	for _, s := range snapshots {
		if !slices.ContainsFunc(s.Tags, func(t string) bool { return ruleTag[t] }) {
			continue
		}
		for key, tags := range filters {
			if key != "" && hasAll(s.Tags, tags) {
				return nil, fmt.Errorf("%w: snapshot %s has the tags %v, so the main policy (for snapshots tagged %q) would include it",
					ErrTagOverlap, s.ShortID, s.Tags, key)
			}
		}
	}
	if len(filters) == 0 {
		return passes, nil
	}
	main := slices.Clone(base)
	for _, key := range slices.Sorted(maps.Keys(filters)) {
		main = append(main, "--tag", key)
	}
	return append(passes, Pass{Args: append(main, p.Args()...)}), nil
}

func hasAll(have, want []string) bool {
	for _, t := range want {
		if !slices.Contains(have, t) {
			return false
		}
	}
	return true
}

// ForgetGroup is one group of "restic forget --json": the snapshots of one
// host and set of paths, split into kept and removed.
type ForgetGroup struct {
	Host   string     `json:"host"`
	Paths  []string   `json:"paths"`
	Keep   []Snapshot `json:"keep"`
	Remove []Snapshot `json:"remove"`
}

// PassResult is the outcome of one pass.
type PassResult struct {
	Tag    string // "" for the main pass
	Groups []ForgetGroup
}

// Removed counts the removed snapshots of all passes.
func Removed(results []PassResult) int {
	n := 0
	for _, r := range results {
		for _, g := range r.Groups {
			n += len(g.Remove)
		}
	}
	return n
}

// Kept returns the snapshots kept by all passes. The passes see disjoint
// sets of snapshots, so after a forget these are all the snapshots left
// (except ones created meanwhile).
func Kept(results []PassResult) []Snapshot {
	var kept []Snapshot
	for _, r := range results {
		for _, g := range r.Groups {
			kept = append(kept, g.Keep...)
		}
	}
	return kept
}

// passes lists the snapshots if the policy has tag rules and returns its
// passes.
func (c *CLI) passes(ctx context.Context, dir string, password []byte, p Policy) ([]Pass, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var list []Snapshot
	if len(p.TagRules) > 0 {
		var err error
		if list, err = c.Snapshots(ctx, dir, password); err != nil {
			return nil, err
		}
	}
	return p.Passes(list)
}

// ForgetPreview runs every pass with "--dry-run --no-lock": it shows what
// the policy would remove and changes nothing (without --no-lock even a dry
// run takes an exclusive lock). The passes see disjoint sets of snapshots,
// so their dry runs add up to what a real forget would do.
func (c *CLI) ForgetPreview(ctx context.Context, dir string, password []byte, p Policy) ([]PassResult, error) {
	passes, err := c.passes(ctx, dir, password, p)
	if err != nil {
		return nil, err
	}
	var results []PassResult
	for _, pass := range passes {
		args := append([]string{"forget", "--dry-run", "--no-lock", "--json"}, pass.Args...)
		var out bytes.Buffer
		if err := c.run(ctx, dir, password, args, &out, nil); err != nil {
			return nil, err
		}
		groups, err := parseForget(out.Bytes())
		if err != nil {
			return nil, err
		}
		results = append(results, PassResult{Tag: pass.Tag, Groups: groups})
	}
	return results, nil
}

func parseForget(data []byte) ([]ForgetGroup, error) {
	// restic prints nothing (not "[]") when no snapshot matches a --tag.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var groups []ForgetGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("parsing restic forget output: %w", err)
	}
	return groups, nil
}
