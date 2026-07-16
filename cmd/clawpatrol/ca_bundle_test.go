package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mintCA returns a self-signed CA cert (PEM + parsed) and its signing
// key, so tests can then sign leaf certs that chain to it. Mirrors the
// shape of inMemoryCertCache (ca_test.go) but exposes the key so a leaf
// can be issued — needed to reproduce #764's "leaf verified against the
// wrong root" failure.
func mintCA(t *testing.T, cn string, serial int64) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return caPEM, caCert, key
}

// mintLeaf issues a server leaf for host, signed by the given CA.
func mintLeaf(t *testing.T, host string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// poolFromPEM builds a CertPool from raw PEM bytes.
func poolFromPEM(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no certs parsed from PEM")
	}
	return p
}

func countPEMCerts(b []byte) int {
	n := 0
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return n
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
}

func TestBuildBundlePEM(t *testing.T) {
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	caPEM, _, _ := mintCA(t, "mitm", 2)

	bundle := buildBundlePEM(sysPEM, caPEM)
	if !bytes.Contains(bundle, sysPEM) {
		t.Error("bundle missing system roots block")
	}
	if !bytes.Contains(bundle, caPEM) {
		t.Error("bundle missing MITM CA block")
	}
	if got := countPEMCerts(bundle); got != 2 {
		t.Errorf("bundle has %d certs, want 2", got)
	}
}

// TestEnsureCABundleVerifiesBothChains is the regression test for #764:
// the combined bundle must verify BOTH a leaf signed by the MITM CA (a
// defined endpoint) AND a leaf signed by a public root (a passthrough
// host), while the MITM-CA-only file fails the passthrough leaf exactly
// as the bug reports.
func TestEnsureCABundleVerifiesBothChains(t *testing.T) {
	mitmPEM, mitmCA, mitmKey := mintCA(t, "clawpatrol mitm", 1)
	sysPEM, sysCA, sysKey := mintCA(t, "public root", 2)

	endpointLeaf := mintLeaf(t, "discord.com", mitmCA, mitmKey) // MITM'd endpoint
	passthroughLeaf := mintLeaf(t, "pypi.org", sysCA, sysKey)   // relayed, real cert

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })

	bundlePath := ensureCABundle(caPath)
	wantPath := filepath.Join(dir, "ca-bundle.crt")
	if bundlePath != wantPath {
		t.Fatalf("ensureCABundle returned %q, want %q", bundlePath, wantPath)
	}
	bundlePEM, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("bundle not written: %v", err)
	}

	bundlePool := poolFromPEM(t, bundlePEM)
	if _, err := endpointLeaf.Verify(x509.VerifyOptions{Roots: bundlePool, DNSName: "discord.com"}); err != nil {
		t.Errorf("bundle should trust MITM endpoint leaf: %v", err)
	}
	if _, err := passthroughLeaf.Verify(x509.VerifyOptions{Roots: bundlePool, DNSName: "pypi.org"}); err != nil {
		t.Errorf("bundle should trust passthrough leaf: %v", err)
	}

	// Negative control: the MITM-CA-only file (today's behavior) cannot
	// verify the passthrough leaf — this is exactly bug #764.
	caOnlyPool := poolFromPEM(t, mitmPEM)
	if _, err := passthroughLeaf.Verify(x509.VerifyOptions{Roots: caOnlyPool, DNSName: "pypi.org"}); err == nil {
		t.Error("MITM-CA-only pool unexpectedly verified passthrough leaf")
	}
}

func TestEnsureCABundleFallbackNoSystemRoots(t *testing.T) {
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return nil, false }
	t.Cleanup(func() { systemRootsReader = prev })

	if got := ensureCABundle(caPath); got != caPath {
		t.Fatalf("ensureCABundle returned %q, want caPath %q", got, caPath)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-bundle.crt")); err == nil {
		t.Error("ca-bundle.crt should not be written without system roots")
	}
}

func TestEnsureCABundleMissingCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt") // never created

	prev := systemRootsReader
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	systemRootsReader = func(string) ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })

	if got := ensureCABundle(caPath); got != caPath {
		t.Fatalf("ensureCABundle returned %q, want caPath %q", got, caPath)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-bundle.crt")); err == nil {
		t.Error("ca-bundle.crt should not be written when ca.crt is absent")
	}
}

// TestEnsureCABundleContentRefresh proves freshness is content-based, not
// mtime-based: a second call with unchanged inputs does not rewrite the file,
// but a system-root change (addition/removal) or a CA rotation is picked up
// even when mtimes wouldn't reveal it.
func TestEnsureCABundleContentRefresh(t *testing.T) {
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	sysPEM, _, _ := mintCA(t, "sysroot", 2)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	roots := sysPEM
	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return roots, true }
	t.Cleanup(func() { systemRootsReader = prev })

	bundlePath := ensureCABundle(caPath)
	first, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}

	// Unchanged inputs → no rewrite (mtime stays put).
	info1, _ := os.Stat(bundlePath)
	if got := ensureCABundle(caPath); got != bundlePath {
		t.Fatalf("second call returned %q, want %q", got, bundlePath)
	}
	info2, _ := os.Stat(bundlePath)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("bundle rewritten despite identical content")
	}

	// System roots change (a root removed / added) with NO ca.crt mtime bump:
	// content-based freshness must still refresh the bundle.
	newRootPEM, _, _ := mintCA(t, "sysroot-2", 3)
	roots = newRootPEM
	ensureCABundle(caPath)
	afterRoots, _ := os.ReadFile(bundlePath)
	if bytes.Equal(first, afterRoots) {
		t.Error("bundle not refreshed after system roots changed")
	}
	if !bytes.Contains(afterRoots, newRootPEM) {
		t.Error("refreshed bundle missing the new system root")
	}

	// CA rotation is likewise picked up by content.
	rotatedPEM, _, _ := mintCA(t, "mitm-rotated", 4)
	if err := os.WriteFile(caPath, rotatedPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	ensureCABundle(caPath)
	rebuilt, _ := os.ReadFile(bundlePath)
	if !bytes.Contains(rebuilt, rotatedPEM) {
		t.Error("bundle missing rotated CA")
	}
}

// TestEnsureCABundleRotationRace reproduces the join-vs-run race: ca.crt is
// rewritten (rotated) while ensureCABundle is mid-build. The final bundle must
// contain the NEW CA, never pin the old one. The injected reader rotates ca.crt
// on its first call, standing in for a concurrent `clawpatrol join`.
func TestEnsureCABundleRotationRace(t *testing.T) {
	oldPEM, _, _ := mintCA(t, "mitm-old", 1)
	newPEM, _, _ := mintCA(t, "mitm-new", 2)
	sysPEM, _, _ := mintCA(t, "sysroot", 3)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, oldPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	raced := false
	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) {
		if !raced {
			raced = true
			// Simulate join landing a new ca.crt after ensureCABundle already
			// read the old one this iteration.
			_ = os.WriteFile(caPath, newPEM, 0o644)
		}
		return sysPEM, true
	}
	t.Cleanup(func() { systemRootsReader = prev })

	bundlePath := ensureCABundle(caPath)
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if !bytes.Contains(bundle, newPEM) {
		t.Error("bundle did not converge on the rotated (new) CA")
	}
	if bytes.Contains(bundle, oldPEM) {
		t.Error("bundle still pins the old CA after rotation")
	}
}

// replaceStyleCAKeys are the vars that override the trust store entirely
// (must point at the combined bundle). NODE_EXTRA_CA_CERTS is additive
// and intentionally excluded — it keeps pointing at the MITM CA alone.
var replaceStyleCAKeys = []string{
	"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	"GIT_SSL_CAINFO", "DENO_CERT", "PIP_CERT", "AWS_CA_BUNDLE",
}

func TestCaPathPushdownVarsBundleForReplaceStyle(t *testing.T) {
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	sysPEM, _, _ := mintCA(t, "sysroot", 2)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "ca-bundle.crt")

	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })

	got := map[string]string{}
	for _, ev := range caPathPushdownVars(caPath) {
		got[ev.Name] = ev.Value
	}
	for _, k := range replaceStyleCAKeys {
		if got[k] != bundlePath {
			t.Errorf("%s = %q, want bundle %q", k, got[k], bundlePath)
		}
	}
	if got["NODE_EXTRA_CA_CERTS"] != caPath {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want ca.crt %q", got["NODE_EXTRA_CA_CERTS"], caPath)
	}
}

// TestCaPathPushdownVarsFallbackAllAtCA proves there is no regression
// when system roots can't be read: every var stays on ca.crt (today's
// behavior — MITM'd hosts keep working, only passthrough stays broken).
func TestCaPathPushdownVarsFallbackAllAtCA(t *testing.T) {
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return nil, false }
	t.Cleanup(func() { systemRootsReader = prev })

	for _, ev := range caPathPushdownVars(caPath) {
		if ev.Value != caPath {
			t.Errorf("%s = %q, want caPath %q (fallback)", ev.Name, ev.Value, caPath)
		}
	}
}

// TestCaPathPushdownVarsPreservesOrigSSLCertFile: when the operator already had
// an SSL_CERT_FILE, caPathPushdownVars must stash it in
// CLAWPATROL_ORIG_SSL_CERT_FILE before overwriting SSL_CERT_FILE with the
// bundle, so a corporate CA survives across nested shells (L2).
func TestCaPathPushdownVarsPreservesOrigSSLCertFile(t *testing.T) {
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	sysPEM, _, _ := mintCA(t, "sysroot", 2)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "ca-bundle.crt")
	corp := filepath.Join(dir, "corp-roots.pem")

	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })
	t.Setenv("SSL_CERT_FILE", corp)
	t.Setenv("CLAWPATROL_ORIG_SSL_CERT_FILE", "")

	got := map[string]string{}
	for _, ev := range caPathPushdownVars(caPath) {
		got[ev.Name] = ev.Value
	}
	if got["SSL_CERT_FILE"] != bundlePath {
		t.Errorf("SSL_CERT_FILE = %q, want bundle %q", got["SSL_CERT_FILE"], bundlePath)
	}
	if got["CLAWPATROL_ORIG_SSL_CERT_FILE"] != corp {
		t.Errorf("CLAWPATROL_ORIG_SSL_CERT_FILE = %q, want %q", got["CLAWPATROL_ORIG_SSL_CERT_FILE"], corp)
	}
}

// TestEnsureCABundleNonConvergingFailsafe (R1): if ca.crt never settles across
// the retry budget, ensureCABundle must return caPath (fail-safe), not a bundle
// it couldn't prove current. The injected reader rewrites ca.crt on every call.
func TestEnsureCABundleNonConvergingFailsafe(t *testing.T) {
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("v0-placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-mint distinct CA payloads so each reader call can rotate ca.crt to a
	// value different from the one ensureCABundle just read (Math.random is
	// unavailable; vary by counter).
	var rotations [][]byte
	for i := 0; i < 10; i++ {
		p, _, _ := mintCA(t, "rot", int64(100+i))
		rotations = append(rotations, p)
	}
	i := 0
	prev := systemRootsReader
	systemRootsReader = func(string) ([]byte, bool) {
		_ = os.WriteFile(caPath, rotations[i%len(rotations)], 0o644)
		i++
		return sysPEM, true
	}
	t.Cleanup(func() { systemRootsReader = prev })

	if got := ensureCABundle(caPath); got != caPath {
		t.Errorf("non-converging ca.crt: got %q, want caPath fail-safe %q", got, caPath)
	}
}
