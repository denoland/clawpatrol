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
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
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
	systemRootsReader = func() ([]byte, bool) { return nil, false }
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
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
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
	systemRootsReader = func() ([]byte, bool) { return roots, true }
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
	systemRootsReader = func() ([]byte, bool) {
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
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
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
	// Isolate ambient SSL_CERT_* so the result never depends on the running
	// shell's trust env (gap-b). With the machine-store reader pinned off,
	// every var must fall back to ca.crt.
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("SSL_CERT_DIR", "")
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return nil, false }
	t.Cleanup(func() { systemRootsReader = prev })

	for _, ev := range caPathPushdownVars(caPath) {
		if ev.Value != caPath {
			t.Errorf("%s = %q, want caPath %q (fallback)", ev.Name, ev.Value, caPath)
		}
	}
}

// TestApplyEnvPushdownVarsForceSetsCAVars (#2): a wrapped agent MUST trust the
// combined bundle even when the operator already had SSL_CERT_FILE (or another
// replace-style CA var) set — otherwise the child trusts only the operator's
// file and no MITM'd endpoint works. Non-CA pushdown vars keep the operator's
// value, and CLAWPATROL_NO_ENV=1 opts out entirely.
func TestApplyEnvPushdownVarsForceSetsCAVars(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/operator/corp-roots.pem") // pre-existing operator value
	t.Setenv("FOO_TOKEN", "operator-value")               // non-CA, must be preserved
	t.Setenv("CLAWPATROL_NO_ENV", "")

	applyEnvPushdownVars([]pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/clawpatrol/ca-bundle.crt"},
		{Name: "FOO_TOKEN", Value: "clawpatrol-value"},
	})

	if got := os.Getenv("SSL_CERT_FILE"); got != "/clawpatrol/ca-bundle.crt" {
		t.Errorf("SSL_CERT_FILE = %q, want the forced bundle path", got)
	}
	if got := os.Getenv("FOO_TOKEN"); got != "operator-value" {
		t.Errorf("FOO_TOKEN = %q, want the operator value preserved", got)
	}

	// CLAWPATROL_NO_ENV=1 disables the whole pushdown, CA vars included.
	t.Setenv("SSL_CERT_FILE", "/operator/corp-roots.pem")
	t.Setenv("CLAWPATROL_NO_ENV", "1")
	applyEnvPushdownVars([]pushdownEnvVar{{Name: "SSL_CERT_FILE", Value: "/clawpatrol/ca-bundle.crt"}})
	if got := os.Getenv("SSL_CERT_FILE"); got != "/operator/corp-roots.pem" {
		t.Errorf("CLAWPATROL_NO_ENV should leave SSL_CERT_FILE untouched, got %q", got)
	}
}

// TestNormalizeCertsPEM (#5): a malformed or header-bearing CERTIFICATE block
// must be dropped, not re-emitted — OpenSSL rejects an entire CA file that
// contains one bad block. Valid certs are deduped and re-encoded cleanly.
func TestNormalizeCertsPEM(t *testing.T) {
	good1, _, _ := mintCA(t, "good1", 1)
	good2, _, _ := mintCA(t, "good2", 2)

	var in []byte
	in = append(in, good1...)
	// A CERTIFICATE block with non-DER garbage bytes.
	in = append(in, []byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n")...)
	// A block carrying PEM headers (AppendCertsFromPEM/OpenSSL reject these).
	in = append(in, []byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END CERTIFICATE-----\n")...)
	in = append(in, good2...)
	in = append(in, good1...) // duplicate

	out := normalizeCertsPEM(in)

	if n := countPEMCerts(out); n != 2 {
		t.Fatalf("normalized cert count = %d, want 2 (dedup + drop malformed)", n)
	}
	if !bytes.Contains(out, good1) || !bytes.Contains(out, good2) {
		t.Error("both valid certs must survive")
	}
	// Every surviving block must parse — proves no garbage leaked through.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(out) {
		t.Error("AppendCertsFromPEM rejected the normalized bundle")
	}
}

// TestEnsureCABundleNonConvergingFailsafe (R1): if ca.crt never settles across
// the retry budget, ensureCABundle must return caPath (fail-safe), not a bundle
// it couldn't prove current. The injected reader rewrites ca.crt on every call.
func TestEnsureCABundleNonConvergingFailsafe(t *testing.T) {
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")

	// Pre-mint distinct VALID CA payloads (a malformed ca.crt would fail safe
	// for a different reason); each reader call rotates ca.crt to a value
	// different from the one ensureCABundle just read.
	var rotations [][]byte
	for i := 0; i < 10; i++ {
		p, _, _ := mintCA(t, "rot", int64(100+i))
		rotations = append(rotations, p)
	}
	if err := os.WriteFile(caPath, rotations[0], 0o644); err != nil {
		t.Fatal(err)
	}
	i := 1
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) {
		_ = os.WriteFile(caPath, rotations[i%len(rotations)], 0o644)
		i++
		return sysPEM, true
	}
	t.Cleanup(func() { systemRootsReader = prev })

	if got := ensureCABundle(caPath); got != caPath {
		t.Errorf("non-converging ca.crt: got %q, want caPath fail-safe %q", got, caPath)
	}
}

// TestEnsureCABundleStaleRootRace (round-4 #1): a slow reader holding roots that
// still contain R must not resurrect R after another writer removed it. The
// injected reader returns roots-with-R on the first read and roots-without-R on
// every re-sample, so ensureCABundle must detect the drift and rebuild — the
// final bundle must NOT contain R.
func TestEnsureCABundleStaleRootRace(t *testing.T) {
	rootR, _, _ := mintCA(t, "root-R-removed", 1)
	rootKeep, _, _ := mintCA(t, "root-kept", 2)
	mitmPEM, _, _ := mintCA(t, "mitm", 3)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	withR := append(append([]byte{}, rootKeep...), rootR...)
	withoutR := rootKeep

	calls := 0
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) {
		defer func() { calls++ }()
		if calls == 0 {
			return withR, true // initial build sees R
		}
		return withoutR, true // R has been removed by the time we re-sample
	}
	t.Cleanup(func() { systemRootsReader = prev })

	bundlePath := ensureCABundle(caPath)
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if bytes.Contains(bundle, rootR) {
		t.Error("removed root R was resurrected into the bundle (stale-snapshot race)")
	}
	if !bytes.Contains(bundle, rootKeep) || !bytes.Contains(bundle, mitmPEM) {
		t.Error("bundle must still contain the kept root and the MITM CA")
	}
}

// TestEnsureCABundleMalformedMITMCA (round-4 #3): a malformed/empty ca.crt must
// NOT yield a system-roots-only bundle returned as success — every defined
// endpoint would fail TLS. ensureCABundle must fail safe (return caPath).
func TestEnsureCABundleMalformedMITMCA(t *testing.T) {
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })

	for _, tc := range []struct {
		name string
		ca   []byte
	}{
		{"garbage", []byte("not a certificate at all")},
		{"empty", []byte{}},
		{"header-bearing", []byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END CERTIFICATE-----\n")},
		{"invalid-der", []byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			caPath := filepath.Join(dir, "ca.crt")
			if err := os.WriteFile(caPath, tc.ca, 0o644); err != nil {
				t.Fatal(err)
			}
			if got := ensureCABundle(caPath); got != caPath {
				t.Errorf("malformed MITM CA: got %q, want caPath fail-safe", got)
			}
			if _, err := os.Stat(filepath.Join(dir, "ca-bundle.crt")); err == nil {
				t.Error("no bundle should be published when the MITM CA is unusable")
			}
		})
	}
}

// TestDropClawpatrolCAVars (round-4 #2): a gateway/plugin-supplied CA var must
// be stripped so it can't override the locally forced bundle path; non-CA vars
// pass through.
func TestDropClawpatrolCAVars(t *testing.T) {
	in := []pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/evil/roots.pem"},
		{Name: "NODE_EXTRA_CA_CERTS", Value: "/evil/extra.pem"},
		{Name: "CODEX_ACCESS_TOKEN", Value: "keep-me"},
	}
	out := dropClawpatrolCAVars(in)
	if len(out) != 1 || out[0].Name != "CODEX_ACCESS_TOKEN" {
		t.Fatalf("dropClawpatrolCAVars = %#v, want only CODEX_ACCESS_TOKEN", out)
	}
}

// TestEnvPushdownVarsFiltersGatewayCAVars (round-4 #2): a gateway that returns
// SSL_CERT_FILE must not win over the local bundle. Covers both the daemon and
// direct-gateway branches.
func TestEnvPushdownVarsFiltersGatewayCAVars(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")
	mitmPEM, _, _ := mintCA(t, "mitm", 1)
	sysPEM, _, _ := mintCA(t, "sysroot", 2)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, mitmPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "ca-bundle.crt")

	prevRoots := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
	prevGW := envPushdownGatewayFetcher
	prevDaemon := envPushdownDaemonFetcher
	t.Cleanup(func() {
		systemRootsReader = prevRoots
		envPushdownGatewayFetcher = prevGW
		envPushdownDaemonFetcher = prevDaemon
	})

	evilVars := []pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/evil/roots.pem"},
		{Name: "CODEX_ACCESS_TOKEN", Value: "from-server"},
	}

	check := func(t *testing.T) {
		got, err := envPushdownVars(caPath)
		if err != nil {
			t.Fatalf("envPushdownVars: %v", err)
		}
		m := map[string]string{}
		for _, ev := range got {
			// last-wins, mirroring the consumer
			m[ev.Name] = ev.Value
		}
		if m["SSL_CERT_FILE"] != bundlePath {
			t.Errorf("SSL_CERT_FILE = %q, want local bundle %q (gateway value must be filtered)", m["SSL_CERT_FILE"], bundlePath)
		}
		if m["CODEX_ACCESS_TOKEN"] != "from-server" {
			t.Errorf("non-CA gateway var dropped: %q", m["CODEX_ACCESS_TOKEN"])
		}
	}

	t.Run("daemon-branch", func(t *testing.T) {
		envPushdownDaemonFetcher = func() ([]pushdownEnvVar, error) { return evilVars, nil }
		check(t)
	})
	t.Run("gateway-branch", func(t *testing.T) {
		envPushdownDaemonFetcher = nil
		envPushdownGatewayFetcher = func(string) ([]pushdownEnvVar, error) { return evilVars, nil }
		check(t)
	})
}

func leafPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestMITMCACertStrictValidation (round-5 #2): only a real CA cert is accepted
// as the mandatory MITM CA. A valid but non-CA leaf can't sign the gateway's
// minted endpoint certs, so it must be rejected — caFingerprintFromPEM accepted
// it.
func TestMITMCACertStrictValidation(t *testing.T) {
	caPEM, caCert, caKey := mintCA(t, "real-ca", 1)
	leaf := mintLeaf(t, "endpoint.example", caCert, caKey) // IsCA=false

	if err := validateMITMCAPEM(caPEM); err != nil {
		t.Errorf("a real CA must be accepted: %v", err)
	}
	if err := validateMITMCAPEM(leafPEM(t, leaf)); err == nil {
		t.Error("a non-CA leaf must be rejected as the MITM CA")
	}
	// Header-bearing and garbage are rejected too.
	if err := validateMITMCAPEM([]byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nZm9v\n-----END CERTIFICATE-----\n")); err == nil {
		t.Error("header-bearing block must be rejected")
	}
	if err := validateMITMCAPEM([]byte("garbage")); err == nil {
		t.Error("garbage must be rejected")
	}
}

// TestCanonicalMITMCAPEM (round-6 #1): exactly one usable CA is accepted and
// returned canonically; an appended second CA, a leaf, and leading/trailing
// junk are all rejected so the fingerprinted cert == the persisted cert.
func TestCanonicalMITMCAPEM(t *testing.T) {
	ca1, _, _ := mintCA(t, "legit", 1)
	ca2, _, _ := mintCA(t, "attacker", 2)
	_, issuer, issuerKey := mintCA(t, "issuer", 3)
	leaf := leafPEM(t, mintLeaf(t, "endpoint", issuer, issuerKey))

	canon, err := canonicalMITMCAPEM(ca1)
	if err != nil {
		t.Fatalf("single CA rejected: %v", err)
	}
	if countPEMCerts(canon) != 1 || !bytes.Equal(canon, ca1) {
		t.Error("canonical form must be the single re-encoded certificate")
	}

	appended := append(append([]byte{}, ca1...), ca2...)
	if _, err := canonicalMITMCAPEM(appended); err == nil {
		t.Error("appended second CA must be rejected (TOFU bypass)")
	}
	if _, err := canonicalMITMCAPEM(leaf); err == nil {
		t.Error("a non-CA leaf must be rejected")
	}
	trailing := append(append([]byte{}, ca1...), []byte("trailing-garbage")...)
	if _, err := canonicalMITMCAPEM(trailing); err == nil {
		t.Error("trailing non-whitespace must be rejected")
	}
	leading := append([]byte("leading-junk\n"), ca1...)
	if _, err := canonicalMITMCAPEM(leading); err == nil {
		t.Error("leading junk before the certificate must be rejected")
	}
}

// TestEnsureCABundleRejectsLeafCA (round-5 #2): a leaf written to ca.crt must
// fail safe — no bundle that can't validate endpoint certs is published.
func TestEnsureCABundleRejectsLeafCA(t *testing.T) {
	sysPEM, _, _ := mintCA(t, "sysroot", 1)
	_, caCert, caKey := mintCA(t, "real-ca", 2)
	leaf := mintLeaf(t, "endpoint.example", caCert, caKey)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, leafPEM(t, leaf), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := systemRootsReader
	systemRootsReader = func() ([]byte, bool) { return sysPEM, true }
	t.Cleanup(func() { systemRootsReader = prev })

	if got := ensureCABundle(caPath); got != caPath {
		t.Errorf("leaf ca.crt: got %q, want caPath fail-safe", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-bundle.crt")); err == nil {
		t.Error("no bundle should be published for a non-CA ca.crt")
	}
}
