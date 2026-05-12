package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/oidcverify"
)

func TestReserveOIDCReplayIsAtomicAndExpires(t *testing.T) {
	db := openTestDB(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(10 * time.Minute)
	verified := &oidcverify.VerifiedToken{Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:denoland/clawpatrol", JWTID: "run-1", TokenHash: "hash-1", ReplayKey: "issuer\x00sub\x00run-1", Expiry: expires}

	reservation, err := reserveOIDCReplay(db, verified, "gha", "ci", now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if reservation.ExpiresAt != expires || reservation.Enrollment != "gha" || reservation.Profile != "ci" {
		t.Fatalf("reservation = %+v", reservation)
	}

	_, err = reserveOIDCReplay(db, verified, "gha", "ci", now.Add(time.Second))
	if !errors.Is(err, errOIDCReplayAlreadyUsed) {
		t.Fatalf("second reserve error = %v", err)
	}
}

func TestCreateOIDCEphemeralLeaseAndActiveLookup(t *testing.T) {
	db := openTestDB(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(30 * time.Minute)
	verified := &oidcverify.VerifiedToken{Issuer: "https://issuer.example.com", Subject: "sub", JWTID: "jti", TokenHash: "hash", ReplayKey: "replay", Expiry: expires}
	reservation, err := reserveOIDCReplay(db, verified, "gha", "ci", now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	lease, err := createOIDCEphemeralLease(db, reservation, oidcLeasePeer{IP: "10.55.0.42", PubKey: "pubkey"}, map[string]any{"repository": "denoland/clawpatrol"}, now, expires)
	if err != nil {
		t.Fatalf("create lease: %v", err)
	}
	if lease.PeerIP != "10.55.0.42" || lease.Profile != "ci" || lease.ExpiresAt != expires {
		t.Fatalf("lease = %+v", lease)
	}

	active, err := activeOIDCEphemeralLeaseForPeer(db, "10.55.0.42", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active == nil || active.PeerIP != "10.55.0.42" || active.Metadata["repository"] != "denoland/clawpatrol" {
		t.Fatalf("active lease = %+v", active)
	}

	expired, err := activeOIDCEphemeralLeaseForPeer(db, "10.55.0.42", expires.Add(time.Nanosecond))
	if err != nil {
		t.Fatalf("expired lookup: %v", err)
	}
	if expired != nil {
		t.Fatalf("expected no active lease after expiry, got %+v", expired)
	}
}

func TestRevokeOIDCEphemeralLease(t *testing.T) {
	db := openTestDB(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	verified := &oidcverify.VerifiedToken{Issuer: "https://issuer.example.com", Subject: "sub", JWTID: "jti", TokenHash: "hash", ReplayKey: "replay", Expiry: now.Add(time.Hour)}
	reservation, err := reserveOIDCReplay(db, verified, "gha", "ci", now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := createOIDCEphemeralLease(db, reservation, oidcLeasePeer{IP: "10.55.0.42", PubKey: "pubkey"}, nil, now, now.Add(time.Hour)); err != nil {
		t.Fatalf("create lease: %v", err)
	}
	if err := revokeOIDCEphemeralLease(db, "10.55.0.42", now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	active, err := activeOIDCEphemeralLeaseForPeer(db, "10.55.0.42", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active != nil {
		t.Fatalf("expected revoked lease to be inactive, got %+v", active)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
