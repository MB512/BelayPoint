package tlscert

import (
	"crypto/x509"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var lan = []netip.Addr{netip.MustParseAddr("192.168.1.10")}

func ensure(t *testing.T, opts Options) Result {
	t.Helper()
	res, err := Ensure(opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func leaf(t *testing.T, res Result) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(res.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFirstStartCreatesCAAndServer(t *testing.T) {
	dir := t.TempDir()
	res := ensure(t, Options{Dir: dir, IPs: lan, DNSNames: []string{"NAS.fritz.box"}})

	if !res.CACreated || !res.Reissued || res.Custom || res.Warning != "" {
		t.Errorf("unexpected result flags: %+v", res)
	}
	c := leaf(t, res)
	if len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(lan[0].AsSlice()) {
		t.Errorf("IPs = %v", c.IPAddresses)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "nas.fritz.box" {
		t.Errorf("DNSNames = %v", c.DNSNames)
	}
	// The chain sent to the browser is leaf + CA.
	if len(res.Certificate.Certificate) != 2 {
		t.Errorf("chain length %d", len(res.Certificate.Certificate))
	}
	// The leaf verifies against the CA for the configured IP.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(res.CAPEM) {
		t.Fatal("CAPEM not parsable")
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: "192.168.1.10"}); err != nil {
		t.Errorf("verify by IP: %v", err)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: "nas.fritz.box"}); err != nil {
		t.Errorf("verify by name: %v", err)
	}
	for _, f := range []string{CAKeyFile, ServerKeyFile} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", f, st.Mode().Perm())
		}
	}
}

func TestRestartKeepsCertificate(t *testing.T) {
	dir := t.TempDir()
	first := ensure(t, Options{Dir: dir, IPs: lan})
	second := ensure(t, Options{Dir: dir, IPs: lan})
	if second.Reissued || second.CACreated {
		t.Errorf("restart reissued: %+v", second)
	}
	if first.ServerFingerprint != second.ServerFingerprint || first.CAFingerprint != second.CAFingerprint {
		t.Error("fingerprints changed on restart")
	}
}

func TestAddressChangeReissuesServerKeepsCA(t *testing.T) {
	dir := t.TempDir()
	first := ensure(t, Options{Dir: dir, IPs: lan})
	second := ensure(t, Options{Dir: dir, IPs: []netip.Addr{netip.MustParseAddr("192.168.1.20")}})
	if !second.Reissued || !strings.Contains(second.Reason, "addresses changed") {
		t.Errorf("want reissue for changed address, got %+v", second)
	}
	if second.OldFingerprint != first.ServerFingerprint {
		t.Error("OldFingerprint not reported")
	}
	if second.CAFingerprint != first.CAFingerprint || second.CACreated {
		t.Error("CA must stay the same")
	}
}

func TestHostnameOrderAndCaseDoNotReissue(t *testing.T) {
	dir := t.TempDir()
	ensure(t, Options{Dir: dir, IPs: lan, DNSNames: []string{"a.local", "B.local"}})
	res := ensure(t, Options{Dir: dir, IPs: lan, DNSNames: []string{"b.local", "a.local"}})
	if res.Reissued {
		t.Errorf("reissued for same names: %s", res.Reason)
	}
}

func TestExpiringCertificateIsRenewed(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	ensure(t, Options{Dir: dir, IPs: lan, Now: func() time.Time { return start }})
	later := start.Add(ServerValidity - RenewBefore + time.Hour)
	res := ensure(t, Options{Dir: dir, IPs: lan, Now: func() time.Time { return later }})
	if !res.Reissued || !strings.Contains(res.Reason, "expires") {
		t.Errorf("want renewal, got %+v", res)
	}
}

func TestNoAddressesFallsBackToLocalhost(t *testing.T) {
	res := ensure(t, Options{Dir: t.TempDir()})
	if res.Warning == "" {
		t.Error("want warning")
	}
	c := leaf(t, res)
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "localhost" {
		t.Errorf("DNSNames = %v", c.DNSNames)
	}
}

func TestResetServerOnly(t *testing.T) {
	dir := t.TempDir()
	first := ensure(t, Options{Dir: dir, IPs: lan})
	if err := Reset(dir, false); err != nil {
		t.Fatal(err)
	}
	second := ensure(t, Options{Dir: dir, IPs: lan})
	if !second.Reissued || second.CACreated || second.CAFingerprint != first.CAFingerprint {
		t.Errorf("want new server cert with same CA: %+v", second)
	}
	if err := Reset(dir, true); err != nil {
		t.Fatal(err)
	}
	third := ensure(t, Options{Dir: dir, IPs: lan})
	if !third.CACreated || third.CAFingerprint == first.CAFingerprint {
		t.Error("want new CA after reset --ca")
	}
}

func TestNewCAInvalidatesOldServerCert(t *testing.T) {
	dir := t.TempDir()
	ensure(t, Options{Dir: dir, IPs: lan})
	for _, f := range []string{CACertFile, CAKeyFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	res := ensure(t, Options{Dir: dir, IPs: lan})
	if !res.Reissued || !strings.Contains(res.Reason, "not signed") {
		t.Errorf("want reissue after CA change, got %+v", res)
	}
}

func TestCustomCertificate(t *testing.T) {
	src := t.TempDir()
	gen := ensure(t, Options{Dir: src, IPs: lan})

	dir := t.TempDir()
	copyFile(t, filepath.Join(src, ServerCertFile), filepath.Join(dir, CustomCertFile))
	copyFile(t, filepath.Join(src, ServerKeyFile), filepath.Join(dir, CustomKeyFile))
	res := ensure(t, Options{Dir: dir, IPs: lan})
	if !res.Custom || res.CAPEM != nil || res.ServerFingerprint != gen.ServerFingerprint {
		t.Errorf("custom cert not used: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, CACertFile)); err == nil {
		t.Error("CA generated although a custom certificate exists")
	}

	// Only one of the two files is a configuration error.
	if err := os.Remove(filepath.Join(dir, CustomKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(Options{Dir: dir, IPs: lan}); err == nil {
		t.Error("want error for custom.crt without custom.key")
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint([]byte("x"))
	if len(fp) != 32*3-1 || strings.Count(fp, ":") != 31 || fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint %q", fp)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
