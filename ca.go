package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type CertCache struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
	mu        sync.RWMutex
	cache     map[string]*tls.Certificate
}

// CertPEM returns the PEM-encoded root certificate. Safe to share
// publicly — it never includes the private key.
func (c *CertCache) CertPEM() []byte { return c.caCertPEM }

// loadOrMintCA returns the gateway's MITM CA, materializing it on
// first call. If the ca_material row is absent, mints a fresh
// ECDSA-P256 key + self-signed cert (10y validity) and inserts.
// Subsequent boots see the row and return the existing material —
// the cert is stable across restarts so peers don't have to
// reinstall the trust anchor.
func loadOrMintCA(db *sql.DB) (*CertCache, error) {
	if db == nil {
		return nil, fmt.Errorf("ca: no db")
	}
	var certPEM, keyPEM []byte
	err := db.QueryRow(`SELECT cert_pem, key_pem FROM ca_material WHERE id = 1`).
		Scan(&certPEM, &keyPEM)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return mintAndStoreCA(db)
	case err != nil:
		return nil, fmt.Errorf("ca read: %w", err)
	}
	return parseCertCache(certPEM, keyPEM)
}

func parseCertCache(certPEM, keyPEM []byte) (*CertCache, error) {
	cblock, _ := pem.Decode(certPEM)
	kblock, _ := pem.Decode(keyPEM)
	if cblock == nil || kblock == nil {
		return nil, errors.New("bad pem")
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertCache{
		caCert:    cert,
		caKey:     key,
		caCertPEM: certPEM,
		cache:     map[string]*tls.Certificate{},
	}, nil
}

func (c *CertCache) mint(host string) (*tls.Certificate, error) {
	c.mu.RLock()
	if t, ok := c.cache[host]; ok {
		c.mu.RUnlock()
		return t, nil
	}
	c.mu.RUnlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, &leafKey.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}
	t := &tls.Certificate{
		Certificate: [][]byte{der, c.caCert.Raw},
		PrivateKey:  leafKey,
	}
	c.mu.Lock()
	c.cache[host] = t
	c.mu.Unlock()
	return t, nil
}

// mintAndStoreCA generates fresh root material and persists it to the
// ca_material row. Called automatically by loadOrMintCA when the row
// is absent. Returns the parsed CertCache so the caller can use it
// without a second DB round-trip.
func mintAndStoreCA(db *sql.DB) (*CertCache, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "clawpatrol gateway CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if _, err := db.Exec(
		`INSERT INTO ca_material (id, cert_pem, key_pem, created_ns) VALUES (1, ?, ?, ?)`,
		certPEM, keyPEM, time.Now().UnixNano(),
	); err != nil {
		return nil, fmt.Errorf("ca insert: %w", err)
	}
	return parseCertCache(certPEM, keyPEM)
}

// caFingerprintFromCert returns the operator-readable SHA-256
// fingerprint of the DER-encoded certificate, formatted as
// uppercase hex byte pairs separated by colons (matches
// `openssl x509 -fingerprint -sha256`). Surfaced on the CLI at
// `clawpatrol join` and on the dashboard approval page so the
// operator can confirm out-of-band that the CA the CLI fetched
// over plain HTTP matches the one the gateway actually serves.
func caFingerprintFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	enc := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/2)
	for i := 0; i < len(enc); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(enc[i : i+2])
	}
	return b.String()
}

// caFingerprintFromPEM decodes the first PEM CERTIFICATE block
// and returns its SHA-256 fingerprint in the colon-separated form
// caFingerprintFromCert produces.
func caFingerprintFromPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("expected PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return caFingerprintFromCert(cert), nil
}
