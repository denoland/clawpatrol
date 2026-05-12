package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/denoland/clawpatrol/internal/oidcverify"
)

var errOIDCReplayAlreadyUsed = errors.New("oidc replay already used")

type oidcReplayReservation struct {
	ReplayKey  string
	Issuer     string
	Subject    string
	JWTID      string
	TokenHash  string
	Enrollment string
	Profile    string
	ReservedAt time.Time
	ExpiresAt  time.Time
}

type oidcLeasePeer struct {
	IP     string
	PubKey string
}

type oidcEphemeralLease struct {
	PeerIP     string
	PubKey     string
	ReplayKey  string
	Issuer     string
	Subject    string
	Enrollment string
	Profile    string
	Metadata   map[string]any
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

func reserveOIDCReplay(db *sql.DB, verified *oidcverify.VerifiedToken, enrollment, profile string, now time.Time) (*oidcReplayReservation, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	if verified == nil || verified.ReplayKey == "" || verified.Issuer == "" || verified.Subject == "" || verified.TokenHash == "" {
		return nil, errors.New("verified oidc token is incomplete")
	}
	if enrollment == "" || profile == "" {
		return nil, errors.New("enrollment and profile are required")
	}
	expires := verified.Expiry
	if expires.IsZero() {
		return nil, errors.New("verified oidc token expiry is required")
	}
	res, err := db.Exec(`
INSERT OR IGNORE INTO oidc_replay_reservations
  (replay_key, issuer, subject, jwt_id, token_hash, enrollment, profile, reserved_ns, expires_ns)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		verified.ReplayKey, verified.Issuer, verified.Subject, verified.JWTID, verified.TokenHash, enrollment, profile, now.UnixNano(), expires.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("insert oidc replay reservation: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("oidc replay reservation result: %w", err)
	}
	if rows == 0 {
		return nil, errOIDCReplayAlreadyUsed
	}
	return &oidcReplayReservation{
		ReplayKey:  verified.ReplayKey,
		Issuer:     verified.Issuer,
		Subject:    verified.Subject,
		JWTID:      verified.JWTID,
		TokenHash:  verified.TokenHash,
		Enrollment: enrollment,
		Profile:    profile,
		ReservedAt: now,
		ExpiresAt:  expires,
	}, nil
}

func createOIDCEphemeralLease(db *sql.DB, reservation *oidcReplayReservation, peer oidcLeasePeer, metadata map[string]any, now, expires time.Time) (*oidcEphemeralLease, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	if reservation == nil || reservation.ReplayKey == "" {
		return nil, errors.New("oidc replay reservation is required")
	}
	if peer.IP == "" || peer.PubKey == "" {
		return nil, errors.New("peer ip and pubkey are required")
	}
	if expires.IsZero() || expires.After(reservation.ExpiresAt) {
		expires = reservation.ExpiresAt
	}
	metadataJSON, err := marshalOIDCMetadata(metadata)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
INSERT INTO oidc_ephemeral_leases
  (peer_ip, pubkey, replay_key, issuer, subject, enrollment, profile, metadata, created_ns, expires_ns)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		peer.IP, peer.PubKey, reservation.ReplayKey, reservation.Issuer, reservation.Subject, reservation.Enrollment, reservation.Profile, metadataJSON, now.UnixNano(), expires.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("insert oidc ephemeral lease: %w", err)
	}
	return &oidcEphemeralLease{
		PeerIP:     peer.IP,
		PubKey:     peer.PubKey,
		ReplayKey:  reservation.ReplayKey,
		Issuer:     reservation.Issuer,
		Subject:    reservation.Subject,
		Enrollment: reservation.Enrollment,
		Profile:    reservation.Profile,
		Metadata:   cloneMetadata(metadata),
		CreatedAt:  now,
		ExpiresAt:  expires,
	}, nil
}

func activeOIDCEphemeralLeaseForPeer(db *sql.DB, peerIP string, now time.Time) (*oidcEphemeralLease, error) {
	if db == nil || peerIP == "" {
		return nil, nil
	}
	row := db.QueryRow(`
SELECT peer_ip, pubkey, replay_key, issuer, subject, enrollment, profile, metadata, created_ns, expires_ns, COALESCE(revoked_ns, 0)
FROM oidc_ephemeral_leases
WHERE peer_ip = ? AND revoked_ns IS NULL AND expires_ns > ?`, peerIP, now.UnixNano())
	lease, err := scanOIDCEphemeralLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return lease, err
}

func revokeOIDCEphemeralLease(db *sql.DB, peerIP string, now time.Time) error {
	if db == nil || peerIP == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE oidc_ephemeral_leases SET revoked_ns = ? WHERE peer_ip = ? AND revoked_ns IS NULL`, now.UnixNano(), peerIP)
	if err != nil {
		return fmt.Errorf("revoke oidc ephemeral lease: %w", err)
	}
	return nil
}

func scanOIDCEphemeralLease(row interface{ Scan(dest ...any) error }) (*oidcEphemeralLease, error) {
	var lease oidcEphemeralLease
	var metadata sql.NullString
	var createdNS, expiresNS, revokedNS int64
	if err := row.Scan(&lease.PeerIP, &lease.PubKey, &lease.ReplayKey, &lease.Issuer, &lease.Subject, &lease.Enrollment, &lease.Profile, &metadata, &createdNS, &expiresNS, &revokedNS); err != nil {
		return nil, err
	}
	lease.CreatedAt = time.Unix(0, createdNS).UTC()
	lease.ExpiresAt = time.Unix(0, expiresNS).UTC()
	if revokedNS != 0 {
		lease.RevokedAt = time.Unix(0, revokedNS).UTC()
	}
	if metadata.Valid && metadata.String != "" {
		if err := json.Unmarshal([]byte(metadata.String), &lease.Metadata); err != nil {
			return nil, fmt.Errorf("decode oidc lease metadata: %w", err)
		}
	}
	if lease.Metadata == nil {
		lease.Metadata = map[string]any{}
	}
	return &lease, nil
}

func marshalOIDCMetadata(metadata map[string]any) (sql.NullString, error) {
	if len(metadata) == 0 {
		return sql.NullString{}, nil
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("encode oidc lease metadata: %w", err)
	}
	return sql.NullString{String: string(b), Valid: true}, nil
}

func cloneMetadata(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
