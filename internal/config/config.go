// Package config reads BelayPoint's configuration from environment variables
// (see "Configuration" in docs/architecture.md). Configuration is read once
// at startup; there is no reload.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the validated configuration.
type Config struct {
	// Listen is the TCP address of the HTTPS listener, e.g. ":8443".
	Listen string
	// ReposDir is the rest-server data directory (repositories + .htpasswd).
	ReposDir string
	// Htpasswd is the path of the rest-server's .htpasswd file.
	Htpasswd string
	// ConfigDir holds BelayPoint's own state (vault, DB, TLS, job logs).
	ConfigDir string

	// LANAddress is the NAS's LAN address with prefix length, e.g.
	// 192.168.1.10/24. The zero value (IsValid() == false) means "not set":
	// the default allowlist applies and the address is not in the certificate.
	LANAddress netip.Prefix
	// Hostnames are extra DNS names for the server certificate.
	Hostnames []string
	// AllowCIDRs are networks allowed in addition to the LAN or default ranges.
	AllowCIDRs []netip.Prefix

	MaxJobs         int
	LockWait        time.Duration
	SessionTTL      time.Duration
	JobLogRetention time.Duration
	// NotifyURL is the webhook for notifications; empty disables them.
	NotifyURL string
	LogLevel  slog.Level
	// Location is the time zone of schedules and of times in the UI (TZ).
	Location *time.Location
}

// Environment variable names.
const (
	EnvLANAddress      = "BELAYPOINT_LAN_ADDRESS"
	EnvHostnames       = "BELAYPOINT_HOSTNAMES"
	EnvAllowCIDRs      = "BELAYPOINT_ALLOW_CIDRS"
	EnvListen          = "BELAYPOINT_LISTEN"
	EnvReposDir        = "BELAYPOINT_REPOS_DIR"
	EnvHtpasswd        = "BELAYPOINT_HTPASSWD" //nolint:gosec // G101: variable name, not a credential
	EnvConfigDir       = "BELAYPOINT_CONFIG_DIR"
	EnvMaxJobs         = "BELAYPOINT_MAX_JOBS"
	EnvLockWait        = "BELAYPOINT_LOCK_WAIT"
	EnvSessionTTL      = "BELAYPOINT_SESSION_TTL"
	EnvNotifyURL       = "BELAYPOINT_NOTIFY_URL"
	EnvJobLogRetention = "BELAYPOINT_JOB_LOG_RETENTION"
	EnvLogLevel        = "BELAYPOINT_LOG_LEVEL"
	EnvTZ              = "TZ"
)

// Defaults.
const (
	DefaultListen    = ":8443"
	DefaultReposDir  = "/repos"
	DefaultConfigDir = "/config"
)

// hostnameRe accepts DNS names made of letters, digits and hyphens per label
// (no wildcards, no trailing dot).
var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Load reads and validates the configuration. getenv is os.Getenv in
// production and a map lookup in tests. All problems are reported together.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	fail := func(name string, err error) { errs = append(errs, fmt.Errorf("%s: %w", name, err)) }

	c := Config{
		Listen:    orDefault(getenv(EnvListen), DefaultListen),
		ReposDir:  filepath.Clean(orDefault(getenv(EnvReposDir), DefaultReposDir)),
		ConfigDir: filepath.Clean(orDefault(getenv(EnvConfigDir), DefaultConfigDir)),
	}
	c.Htpasswd = filepath.Clean(orDefault(getenv(EnvHtpasswd), filepath.Join(c.ReposDir, ".htpasswd")))
	for name, dir := range map[string]string{EnvReposDir: c.ReposDir, EnvConfigDir: c.ConfigDir, EnvHtpasswd: c.Htpasswd} {
		if !filepath.IsAbs(dir) {
			fail(name, errors.New("must be an absolute path"))
		}
	}

	if v := strings.TrimSpace(getenv(EnvLANAddress)); v != "" {
		p, err := netip.ParsePrefix(v)
		switch {
		case err != nil:
			fail(EnvLANAddress, fmt.Errorf("want address/prefix like 192.168.1.10/24: %w", err))
		case p.Addr().IsUnspecified() || p.Addr().IsLoopback():
			fail(EnvLANAddress, errors.New("must be the NAS's LAN address, not unspecified or loopback"))
		case p.Addr() == p.Masked().Addr() && p.Bits() < p.Addr().BitLen():
			fail(EnvLANAddress, errors.New("give the NAS's own address with the prefix (192.168.1.10/24), not the network address"))
		default:
			c.LANAddress = p
		}
	}

	for _, h := range splitList(getenv(EnvHostnames)) {
		if !hostnameRe.MatchString(h) || len(h) > 253 {
			fail(EnvHostnames, fmt.Errorf("invalid host name %q", h))
			continue
		}
		c.Hostnames = append(c.Hostnames, strings.ToLower(h))
	}

	for _, s := range splitList(getenv(EnvAllowCIDRs)) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			fail(EnvAllowCIDRs, fmt.Errorf("invalid network %q: %w", s, err))
			continue
		}
		c.AllowCIDRs = append(c.AllowCIDRs, p.Masked())
	}

	var err error
	if c.MaxJobs, err = intVar(getenv(EnvMaxJobs), 1, 1, 16); err != nil {
		fail(EnvMaxJobs, err)
	}
	if c.LockWait, err = durationVar(getenv(EnvLockWait), 30*time.Minute, 0); err != nil {
		fail(EnvLockWait, err)
	}
	if c.SessionTTL, err = durationVar(getenv(EnvSessionTTL), 8*time.Hour, 5*time.Minute); err != nil {
		fail(EnvSessionTTL, err)
	}
	if c.JobLogRetention, err = durationVar(getenv(EnvJobLogRetention), 90*24*time.Hour, 0); err != nil {
		fail(EnvJobLogRetention, err)
	}

	if v := strings.TrimSpace(getenv(EnvNotifyURL)); v != "" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			fail(EnvNotifyURL, errors.New("must be an http(s) URL"))
		} else {
			c.NotifyURL = v
		}
	}

	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			fail(EnvLogLevel, errors.New("want debug, info, warn or error"))
		}
	}

	c.Location = time.UTC
	if v := strings.TrimSpace(getenv(EnvTZ)); v != "" {
		// Go silently falls back to UTC for an unknown TZ; we refuse instead,
		// so schedules never run at an unexpected hour.
		loc, err := time.LoadLocation(v)
		if err != nil {
			fail(EnvTZ, fmt.Errorf("unknown time zone %q", v))
		} else {
			c.Location = loc
		}
	}

	return c, errors.Join(errs...)
}

// HasLANAddress reports whether BELAYPOINT_LAN_ADDRESS is set (strict mode).
func (c Config) HasLANAddress() bool { return c.LANAddress.IsValid() }

func orDefault(v, def string) string {
	if v = strings.TrimSpace(v); v == "" {
		return def
	}
	return v
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func intVar(v string, def, minVal, maxVal int) (int, error) {
	if v = strings.TrimSpace(v); v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minVal || n > maxVal {
		return 0, fmt.Errorf("want a number from %d to %d", minVal, maxVal)
	}
	return n, nil
}

func durationVar(v string, def, minVal time.Duration) (time.Duration, error) {
	if v = strings.TrimSpace(v); v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < minVal {
		return 0, fmt.Errorf("want a Go duration like 30m or 8h, at least %s", minVal)
	}
	return d, nil
}
