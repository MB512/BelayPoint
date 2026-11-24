package config

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.ReposDir != "/repos" || c.ConfigDir != "/config" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.Htpasswd != "/repos/.htpasswd" {
		t.Errorf("Htpasswd = %q", c.Htpasswd)
	}
	if c.HasLANAddress() {
		t.Error("LAN address set without variable")
	}
	if c.MaxJobs != 1 || c.LockWait != 30*time.Minute || c.SessionTTL != 8*time.Hour {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.Location != time.UTC || c.LogLevel != slog.LevelInfo {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestLoadValues(t *testing.T) {
	c, err := Load(env(map[string]string{
		EnvLANAddress:      "192.168.1.10/24",
		EnvHostnames:       "NAS.fritz.box, nas.local",
		EnvAllowCIDRs:      "10.8.0.1/24,fd00::/8",
		EnvReposDir:        "/data/restic/",
		EnvMaxJobs:         "2",
		EnvLockWait:        "1h",
		EnvLogLevel:        "debug",
		EnvTZ:              "Europe/Berlin",
		EnvNotifyURL:       "https://ntfy.sh/topic",
		EnvNotifyToken:     "tk_abc123",
		EnvSessionTTL:      "30m",
		EnvJobLogRetention: "0",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.LANAddress != netip.MustParsePrefix("192.168.1.10/24") {
		t.Errorf("LANAddress = %v", c.LANAddress)
	}
	if strings.Join(c.Hostnames, ",") != "nas.fritz.box,nas.local" {
		t.Errorf("Hostnames = %v", c.Hostnames)
	}
	if len(c.AllowCIDRs) != 2 || c.AllowCIDRs[0] != netip.MustParsePrefix("10.8.0.0/24") {
		t.Errorf("AllowCIDRs = %v (want masked networks)", c.AllowCIDRs)
	}
	if c.ReposDir != "/data/restic" || c.Htpasswd != "/data/restic/.htpasswd" {
		t.Errorf("paths: %q %q", c.ReposDir, c.Htpasswd)
	}
	if c.NotifyURL != "https://ntfy.sh/topic" || c.NotifyToken != "tk_abc123" {
		t.Errorf("notify: %q %q", c.NotifyURL, c.NotifyToken)
	}
	if c.MaxJobs != 2 || c.LockWait != time.Hour || c.LogLevel != slog.LevelDebug || c.Location.String() != "Europe/Berlin" {
		t.Errorf("values: %+v", c)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"LAN without prefix", EnvLANAddress, "192.168.1.10"},
		{"LAN network address", EnvLANAddress, "192.168.1.0/24"},
		{"LAN loopback", EnvLANAddress, "127.0.0.1/8"},
		{"LAN garbage", EnvLANAddress, "nas"},
		{"hostname wildcard", EnvHostnames, "*.local"},
		{"hostname underscore", EnvHostnames, "my_nas"},
		{"cidr garbage", EnvAllowCIDRs, "10.8.0.0"},
		{"max jobs zero", EnvMaxJobs, "0"},
		{"max jobs text", EnvMaxJobs, "many"},
		{"lock wait", EnvLockWait, "soon"},
		{"session too short", EnvSessionTTL, "1m"},
		{"notify scheme", EnvNotifyURL, "ftp://example.org"},
		{"notify token without URL", EnvNotifyToken, "tk_abc"},
		{"log level", EnvLogLevel, "loud"},
		{"tz", EnvTZ, "Mars/Olympus"},
		{"relative repos", EnvReposDir, "repos"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(env(map[string]string{tt.key: tt.value}))
			if err == nil || !strings.Contains(err.Error(), tt.key) {
				t.Errorf("want error mentioning %s, got %v", tt.key, err)
			}
		})
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(env(map[string]string{EnvMaxJobs: "0", EnvTZ: "Nowhere/Zone"}))
	if err == nil || !strings.Contains(err.Error(), EnvMaxJobs) || !strings.Contains(err.Error(), EnvTZ) {
		t.Errorf("want both errors, got %v", err)
	}
}
