// Package tlscert provides the HTTPS certificate (see "TLS" in
// docs/architecture.md): a local CA and a server certificate signed by it,
// generated in the config directory and reissued when the configured
// addresses change or the certificate is about to expire. An operator can
// provide custom.crt/custom.key instead; those are used unchanged.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/atomicfile"
)

// File names inside the TLS directory.
const (
	CACertFile     = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
	CustomCertFile = "custom.crt"
	CustomKeyFile  = "custom.key"
)

// Lifetimes and renewal threshold.
const (
	CAValidity     = 10 * 365 * 24 * time.Hour
	ServerValidity = 365 * 24 * time.Hour
	RenewBefore    = 30 * 24 * time.Hour
)

// Options describe the wanted server certificate.
type Options struct {
	// Dir is the TLS directory, e.g. /config/tls. It is created if missing.
	Dir string
	// IPs and DNSNames are the subject alternative names. If both are empty,
	// localhost and 127.0.0.1 are used (the browser will then report a name
	// mismatch; see Result.Warning).
	IPs      []netip.Addr
	DNSNames []string
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Result is the certificate to serve plus what happened, for the log.
type Result struct {
	Certificate tls.Certificate
	// Custom is true if custom.crt/custom.key are used.
	Custom bool
	// CAPEM is the CA certificate in PEM form (nil when Custom).
	CAPEM []byte
	// CAFingerprint and ServerFingerprint are SHA-256 fingerprints of the
	// DER certificates, formatted like browsers show them (AB:CD:...).
	CAFingerprint     string
	ServerFingerprint string
	// CACreated is true if a new CA was generated in this call.
	CACreated bool
	// Reissued is true if a new server certificate was generated; Reason says
	// why and OldFingerprint is the replaced certificate's (if any).
	Reissued       bool
	Reason         string
	OldFingerprint string
	// Warning is set when no address or host name is configured.
	Warning string
}

// Ensure returns the certificate to serve, generating or reissuing files as
// needed.
func Ensure(opts Options) (Result, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("creating TLS directory: %w", err)
	}

	if custom, err := loadCustom(opts.Dir); err != nil || custom != nil {
		if err != nil {
			return Result{}, err
		}
		return *custom, nil
	}

	var res Result
	ips, names := opts.IPs, normalizeNames(opts.DNSNames)
	if len(ips) == 0 && len(names) == 0 {
		ips = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		names = []string{"localhost"}
		res.Warning = "no BELAYPOINT_LAN_ADDRESS or BELAYPOINT_HOSTNAMES set: the certificate is only valid for localhost and browsers will report a name mismatch"
	}

	caCert, caKey, created, err := loadOrCreateCA(opts.Dir, now())
	if err != nil {
		return Result{}, err
	}
	res.CACreated = created
	res.CAPEM = pemCert(caCert.Raw)
	res.CAFingerprint = Fingerprint(caCert.Raw)

	reason, old := needsReissue(opts.Dir, caCert, ips, names, now())
	if reason != "" {
		if err := issueServer(opts.Dir, caCert, caKey, ips, names, now()); err != nil {
			return Result{}, err
		}
		res.Reissued, res.Reason = true, reason
		if old != nil {
			res.OldFingerprint = Fingerprint(old.Raw)
		}
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join(opts.Dir, ServerCertFile), filepath.Join(opts.Dir, ServerKeyFile))
	if err != nil {
		return Result{}, fmt.Errorf("loading server certificate: %w", err)
	}
	// Send the CA along, so a browser that trusts it can build the chain.
	pair.Certificate = append(pair.Certificate, caCert.Raw)
	res.Certificate = pair
	res.ServerFingerprint = Fingerprint(pair.Certificate[0])
	return res, nil
}

// Reset deletes the generated server certificate (and with ca also the CA),
// so the next start generates new ones. Custom certificates are not touched.
func Reset(dir string, ca bool) error {
	files := []string{ServerCertFile, ServerKeyFile}
	if ca {
		files = append(files, CACertFile, CAKeyFile)
	}
	for _, f := range files {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", f, err)
		}
	}
	return nil
}

// Fingerprint formats the SHA-256 of a DER certificate as AB:CD:....
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func loadCustom(dir string) (*Result, error) {
	certPath, keyPath := filepath.Join(dir, CustomCertFile), filepath.Join(dir, CustomKeyFile)
	certOK, keyOK := exists(certPath), exists(keyPath)
	switch {
	case !certOK && !keyOK:
		return nil, nil
	case certOK != keyOK:
		return nil, fmt.Errorf("custom certificate: both %s and %s are needed", CustomCertFile, CustomKeyFile)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading custom certificate: %w", err)
	}
	return &Result{Certificate: pair, Custom: true, ServerFingerprint: Fingerprint(pair.Certificate[0])}, nil
}

func loadOrCreateCA(dir string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, bool, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	if exists(certPath) || exists(keyPath) {
		cert, key, err := loadPair(certPath, keyPath)
		if errors.Is(err, fs.ErrPermission) {
			return nil, nil, false, fmt.Errorf("loading CA: %w (the files belong to another user; "+
				"run the container as their owner or chown the config directory)", err)
		}
		if err != nil {
			return nil, nil, false, fmt.Errorf("loading CA (remove %s and %s to create a new one): %w", CACertFile, CAKeyFile, err)
		}
		if !cert.IsCA {
			return nil, nil, false, fmt.Errorf("%s is not a CA certificate", CACertFile)
		}
		return cert, key, false, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, fmt.Errorf("generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, false, err
	}
	// The serial goes into the name, so several installations can be told
	// apart in the browser's certificate list.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "BelayPoint local CA " + serial.Text(16)[:8], Organization: []string{"BelayPoint"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("creating CA certificate: %w", err)
	}
	if err := writePair(certPath, keyPath, der, key); err != nil {
		return nil, nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parsing new CA certificate: %w", err)
	}
	return cert, key, true, nil
}

// needsReissue returns why the server certificate must be (re)issued, or ""
// if it can be kept, plus the existing certificate if one could be parsed.
func needsReissue(dir string, ca *x509.Certificate, ips []netip.Addr, names []string, now time.Time) (string, *x509.Certificate) {
	cert, _, err := loadPair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "no server certificate yet", nil
	case err != nil:
		return "server certificate unreadable: " + err.Error(), nil
	case cert.CheckSignatureFrom(ca) != nil:
		return "server certificate not signed by the current CA", cert
	case !sameSANs(cert, ips, names):
		return fmt.Sprintf("configured addresses changed (certificate: %s; configured: %s)",
			sanString(certIPs(cert), cert.DNSNames), sanString(ips, names)), cert
	case cert.NotAfter.Sub(now) < RenewBefore:
		return "server certificate expires on " + cert.NotAfter.Format(time.DateOnly), cert
	}
	return "", cert
}

func issueServer(dir string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ips []netip.Addr, names []string, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	cn := "BelayPoint"
	if len(names) > 0 {
		cn = names[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"BelayPoint"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ServerValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating server certificate: %w", err)
	}
	return writePair(filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile), der, key)
}

func loadPair(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("key does not match certificate")
	}
	return cert, key, nil
}

// writePair writes key and certificate atomically (temp file + rename), the
// key with mode 0600. The key is written first, so a crash in between leaves
// a mismatching pair, which needsReissue/loadOrCreateCA detect.
func writePair(certPath, keyPath string, der []byte, key *ecdsa.PrivateKey) error {
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encoding key: %w", err)
	}
	if err := atomicfile.Write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		return err
	}
	return atomicfile.Write(certPath, pemCert(der), 0o644)
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	// Make sure the hex form has at least 8 digits (used in the CA name).
	return n.SetBit(n, 126, 1), nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func normalizeNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func certIPs(c *x509.Certificate) []netip.Addr {
	out := make([]netip.Addr, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func sameSANs(c *x509.Certificate, ips []netip.Addr, names []string) bool {
	have := certIPs(c)
	want := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		want = append(want, ip.Unmap())
	}
	slices.SortFunc(have, func(a, b netip.Addr) int { return a.Compare(b) })
	slices.SortFunc(want, func(a, b netip.Addr) int { return a.Compare(b) })
	haveNames := normalizeNames(c.DNSNames)
	slices.Sort(haveNames)
	wantNames := slices.Clone(names)
	slices.Sort(wantNames)
	return slices.Equal(have, want) && slices.Equal(haveNames, wantNames)
}

func sanString(ips []netip.Addr, names []string) string {
	var parts []string
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	parts = append(parts, names...)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
