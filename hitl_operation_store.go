package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type HITLOperationState string

const (
	HITLOperationStateSyncWaiting             HITLOperationState = "sync_waiting"
	HITLOperationStatePendingApproval         HITLOperationState = "pending_approval"
	HITLOperationStateApprovedWaitingForRetry HITLOperationState = "approved_waiting_for_retry"
	HITLOperationStateDenied                  HITLOperationState = "denied"
	HITLOperationStateExpired                 HITLOperationState = "expired"
	HITLOperationStateExecutingUpstream       HITLOperationState = "executing_upstream"
	HITLOperationStateUpstreamSucceeded       HITLOperationState = "upstream_succeeded"
	HITLOperationStateUpstreamFailed          HITLOperationState = "upstream_failed"
	HITLOperationStateClientDisconnected      HITLOperationState = "client_disconnected"
)

var (
	ErrHITLOperationNotFound     = errors.New("hitl operation not found")
	ErrHITLOperationConflict     = errors.New("hitl operation state conflict")
	ErrHITLRetryNotApproved      = errors.New("hitl retry not approved")
	ErrHITLRetryExpired          = errors.New("hitl retry expired")
	ErrHITLRetryMismatch         = errors.New("hitl retry mismatch")
	ErrHITLGrantAlreadyConsumed  = errors.New("hitl retry grant already consumed")
	ErrHITLOperationStoreInvalid = errors.New("invalid hitl operation")
)

type HITLOperationStore struct {
	db *sql.DB
}

type HITLOperationCreate struct {
	ID                  string
	State               HITLOperationState
	ProfileID           string
	PrincipalID         string
	EndpointID          string
	ApprovalRuleID      string
	ApproverID          string
	Method              string
	Scheme              string
	Host                string
	RedactedPath        string
	RedactedQuery       string
	RedactedHeadersJSON string
	AuthBindingID       string
	FingerprintVersion  string
	HMACKeyID           string
	RequestFingerprint  string
	CreatedAt           time.Time
	SyncWaitDeadline    time.Time
	ApprovalExpiresAt   time.Time
	RetryExpiresAt      time.Time
}

type HITLOperationTransition struct {
	ID                         string
	FromState                  HITLOperationState
	ToState                    HITLOperationState
	ExpectedVersion            int64
	Now                        time.Time
	RetryExpiresAt             time.Time
	ExpiredReason              string
	TerminalRetentionExpiresAt time.Time
	UpstreamCalled             bool
	LastError                  string
}

type HITLRetryGrantConsume struct {
	ID                 string
	ProfileID          string
	PrincipalID        string
	AuthBindingID      string
	FingerprintVersion string
	HMACKeyID          string
	RequestFingerprint string
	ConsumedBy         string
	Now                time.Time
}

type HITLOperation struct {
	ID                         string
	State                      HITLOperationState
	Version                    int64
	ProfileID                  string
	PrincipalID                string
	EndpointID                 string
	ApprovalRuleID             string
	ApproverID                 string
	Method                     string
	Scheme                     string
	Host                       string
	RedactedPath               string
	RedactedQuery              string
	RedactedHeadersJSON        string
	AuthBindingID              string
	FingerprintVersion         string
	HMACKeyID                  string
	RequestFingerprint         string
	CreatedAt                  time.Time
	SyncWaitDeadline           time.Time
	ApprovalExpiresAt          time.Time
	RetryExpiresAt             *time.Time
	ExpiredReason              string
	TerminalAt                 *time.Time
	TerminalRetentionExpiresAt *time.Time
	UpstreamCalled             bool
	GrantConsumedAt            *time.Time
	GrantConsumedBy            string
	ApproverMessageRef         string
	DashboardRef               string
	LastError                  string
}

func NewHITLOperationStore(db *sql.DB) *HITLOperationStore {
	return &HITLOperationStore{db: db}
}

func (s *HITLOperationStore) Create(ctx context.Context, in HITLOperationCreate) (HITLOperation, error) {
	if s == nil || s.db == nil {
		return HITLOperation{}, fmt.Errorf("%w: nil store", ErrHITLOperationStoreInvalid)
	}
	if in.ID == "" {
		in.ID = newReqID()
	}
	if in.State == "" {
		in.State = HITLOperationStateSyncWaiting
	}
	if err := validateHITLOperationCreate(in); err != nil {
		return HITLOperation{}, err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO hitl_operations (
  id, state, version,
  profile_id, principal_id, endpoint_id, approval_rule_id, approver_id,
  method, scheme, host, redacted_path, redacted_query, redacted_headers_json,
  auth_binding_id, fingerprint_version, hmac_key_id, request_fingerprint,
  created_ns, sync_wait_deadline_ns, approval_expires_ns, retry_expires_ns
) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, string(in.State),
		in.ProfileID, in.PrincipalID, in.EndpointID, in.ApprovalRuleID, in.ApproverID,
		in.Method, in.Scheme, in.Host, in.RedactedPath, nullString(in.RedactedQuery), nullString(in.RedactedHeadersJSON),
		in.AuthBindingID, in.FingerprintVersion, in.HMACKeyID, in.RequestFingerprint,
		timeNS(in.CreatedAt), timeNS(in.SyncWaitDeadline), timeNS(in.ApprovalExpiresAt), nullTimeNS(in.RetryExpiresAt),
	)
	if err != nil {
		return HITLOperation{}, err
	}
	return s.get(ctx, in.ID)
}

func (s *HITLOperationStore) GetForPrincipal(ctx context.Context, id, profileID, principalID string) (HITLOperation, error) {
	if s == nil || s.db == nil {
		return HITLOperation{}, fmt.Errorf("%w: nil store", ErrHITLOperationStoreInvalid)
	}
	return s.scanOne(ctx, `SELECT `+hitlOperationColumns+` FROM hitl_operations WHERE id = ? AND profile_id = ? AND principal_id = ?`, id, profileID, principalID)
}

func (s *HITLOperationStore) Transition(ctx context.Context, tr HITLOperationTransition) (HITLOperation, error) {
	if s == nil || s.db == nil {
		return HITLOperation{}, fmt.Errorf("%w: nil store", ErrHITLOperationStoreInvalid)
	}
	if tr.ID == "" || tr.FromState == "" || tr.ToState == "" || tr.ExpectedVersion <= 0 || tr.Now.IsZero() {
		return HITLOperation{}, fmt.Errorf("%w: incomplete transition", ErrHITLOperationStoreInvalid)
	}
	if !isKnownHITLOperationState(tr.FromState) || !isKnownHITLOperationState(tr.ToState) {
		return HITLOperation{}, fmt.Errorf("%w: unknown transition state", ErrHITLOperationStoreInvalid)
	}
	sets := []string{"state = ?", "version = version + 1"}
	args := []any{string(tr.ToState)}
	if !tr.RetryExpiresAt.IsZero() {
		sets = append(sets, "retry_expires_ns = ?")
		args = append(args, timeNS(tr.RetryExpiresAt))
	}
	if tr.ExpiredReason != "" {
		sets = append(sets, "expired_reason = ?")
		args = append(args, tr.ExpiredReason)
	}
	if isTerminalHITLOperationState(tr.ToState) {
		sets = append(sets, "terminal_ns = ?")
		args = append(args, timeNS(tr.Now))
		if !tr.TerminalRetentionExpiresAt.IsZero() {
			sets = append(sets, "terminal_retention_expires_ns = ?")
			args = append(args, timeNS(tr.TerminalRetentionExpiresAt))
		}
	}
	if tr.UpstreamCalled || tr.ToState == HITLOperationStateExecutingUpstream {
		sets = append(sets, "upstream_called = 1")
	}
	if tr.LastError != "" {
		sets = append(sets, "last_error = ?")
		args = append(args, tr.LastError)
	}
	args = append(args, tr.ID, string(tr.FromState), tr.ExpectedVersion)
	res, err := s.db.ExecContext(ctx, `UPDATE hitl_operations SET `+strings.Join(sets, ", ")+` WHERE id = ? AND state = ? AND version = ?`, args...)
	if err != nil {
		return HITLOperation{}, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return HITLOperation{}, err
	}
	if changed != 1 {
		return HITLOperation{}, ErrHITLOperationConflict
	}
	return s.get(ctx, tr.ID)
}

func (s *HITLOperationStore) ConsumeRetryGrant(ctx context.Context, in HITLRetryGrantConsume) (HITLOperation, error) {
	if s == nil || s.db == nil {
		return HITLOperation{}, fmt.Errorf("%w: nil store", ErrHITLOperationStoreInvalid)
	}
	if in.ID == "" || in.ProfileID == "" || in.PrincipalID == "" || in.AuthBindingID == "" || in.FingerprintVersion == "" || in.HMACKeyID == "" || in.RequestFingerprint == "" || in.ConsumedBy == "" || in.Now.IsZero() {
		return HITLOperation{}, fmt.Errorf("%w: incomplete retry consume", ErrHITLOperationStoreInvalid)
	}
	op, err := s.GetForPrincipal(ctx, in.ID, in.ProfileID, in.PrincipalID)
	if err != nil {
		return HITLOperation{}, err
	}
	if op.GrantConsumedAt != nil {
		return HITLOperation{}, ErrHITLGrantAlreadyConsumed
	}
	if op.State != HITLOperationStateApprovedWaitingForRetry {
		return HITLOperation{}, ErrHITLRetryNotApproved
	}
	if op.RetryExpiresAt == nil || !in.Now.Before(*op.RetryExpiresAt) {
		return HITLOperation{}, ErrHITLRetryExpired
	}
	if op.AuthBindingID != in.AuthBindingID || op.FingerprintVersion != in.FingerprintVersion || op.HMACKeyID != in.HMACKeyID || op.RequestFingerprint != in.RequestFingerprint {
		return HITLOperation{}, ErrHITLRetryMismatch
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE hitl_operations
SET state = ?, version = version + 1, upstream_called = 1, grant_consumed_ns = ?, grant_consumed_by = ?
WHERE id = ?
  AND profile_id = ?
  AND principal_id = ?
  AND state = ?
  AND version = ?
  AND grant_consumed_ns IS NULL
  AND retry_expires_ns > ?
  AND auth_binding_id = ?
  AND fingerprint_version = ?
  AND hmac_key_id = ?
  AND request_fingerprint = ?`,
		string(HITLOperationStateExecutingUpstream), timeNS(in.Now), in.ConsumedBy,
		in.ID, in.ProfileID, in.PrincipalID, string(HITLOperationStateApprovedWaitingForRetry), op.Version, timeNS(in.Now), in.AuthBindingID, in.FingerprintVersion, in.HMACKeyID, in.RequestFingerprint,
	)
	if err != nil {
		return HITLOperation{}, err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return HITLOperation{}, err
	}
	if changed != 1 {
		latest, latestErr := s.GetForPrincipal(ctx, in.ID, in.ProfileID, in.PrincipalID)
		if latestErr != nil {
			return HITLOperation{}, latestErr
		}
		if latest.GrantConsumedAt != nil {
			return HITLOperation{}, ErrHITLGrantAlreadyConsumed
		}
		if latest.State != HITLOperationStateApprovedWaitingForRetry {
			return HITLOperation{}, ErrHITLRetryNotApproved
		}
		if latest.RetryExpiresAt == nil || !in.Now.Before(*latest.RetryExpiresAt) {
			return HITLOperation{}, ErrHITLRetryExpired
		}
		if latest.AuthBindingID != in.AuthBindingID || latest.FingerprintVersion != in.FingerprintVersion || latest.HMACKeyID != in.HMACKeyID || latest.RequestFingerprint != in.RequestFingerprint {
			return HITLOperation{}, ErrHITLRetryMismatch
		}
		return HITLOperation{}, ErrHITLOperationConflict
	}
	return s.GetForPrincipal(ctx, in.ID, in.ProfileID, in.PrincipalID)
}

const hitlOperationColumns = `
id, state, version,
profile_id, principal_id, endpoint_id, approval_rule_id, approver_id,
method, scheme, host, redacted_path, redacted_query, redacted_headers_json,
auth_binding_id, fingerprint_version, hmac_key_id, request_fingerprint,
created_ns, sync_wait_deadline_ns, approval_expires_ns, retry_expires_ns,
expired_reason, terminal_ns, terminal_retention_expires_ns,
upstream_called, grant_consumed_ns, grant_consumed_by, approver_message_ref, dashboard_ref, last_error`

func (s *HITLOperationStore) get(ctx context.Context, id string) (HITLOperation, error) {
	return s.scanOne(ctx, `SELECT `+hitlOperationColumns+` FROM hitl_operations WHERE id = ?`, id)
}

func (s *HITLOperationStore) scanOne(ctx context.Context, query string, args ...any) (HITLOperation, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	var op HITLOperation
	var state string
	var redactedQuery, redactedHeaders sql.NullString
	var retryExpiresNS, terminalNS, terminalRetentionNS, grantConsumedNS sql.NullInt64
	var expiredReason, grantConsumedBy, approverMessageRef, dashboardRef, lastError sql.NullString
	var upstreamCalled int
	var createdNS, syncWaitDeadlineNS, approvalExpiresNS int64
	err := row.Scan(
		&op.ID, &state, &op.Version,
		&op.ProfileID, &op.PrincipalID, &op.EndpointID, &op.ApprovalRuleID, &op.ApproverID,
		&op.Method, &op.Scheme, &op.Host, &op.RedactedPath, &redactedQuery, &redactedHeaders,
		&op.AuthBindingID, &op.FingerprintVersion, &op.HMACKeyID, &op.RequestFingerprint,
		&createdNS, &syncWaitDeadlineNS, &approvalExpiresNS, &retryExpiresNS,
		&expiredReason, &terminalNS, &terminalRetentionNS,
		&upstreamCalled, &grantConsumedNS, &grantConsumedBy, &approverMessageRef, &dashboardRef, &lastError,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return HITLOperation{}, ErrHITLOperationNotFound
	}
	if err != nil {
		return HITLOperation{}, err
	}
	op.State = HITLOperationState(state)
	op.RedactedQuery = redactedQuery.String
	op.RedactedHeadersJSON = redactedHeaders.String
	op.CreatedAt = timeFromNS(createdNS)
	op.SyncWaitDeadline = timeFromNS(syncWaitDeadlineNS)
	op.ApprovalExpiresAt = timeFromNS(approvalExpiresNS)
	op.RetryExpiresAt = nullTimeFromNS(retryExpiresNS)
	op.ExpiredReason = expiredReason.String
	op.TerminalAt = nullTimeFromNS(terminalNS)
	op.TerminalRetentionExpiresAt = nullTimeFromNS(terminalRetentionNS)
	op.UpstreamCalled = upstreamCalled != 0
	op.GrantConsumedAt = nullTimeFromNS(grantConsumedNS)
	op.GrantConsumedBy = grantConsumedBy.String
	op.ApproverMessageRef = approverMessageRef.String
	op.DashboardRef = dashboardRef.String
	op.LastError = lastError.String
	return op, nil
}

func validateHITLOperationCreate(in HITLOperationCreate) error {
	for name, value := range map[string]string{
		"id":                  in.ID,
		"profile_id":          in.ProfileID,
		"principal_id":        in.PrincipalID,
		"endpoint_id":         in.EndpointID,
		"approval_rule_id":    in.ApprovalRuleID,
		"approver_id":         in.ApproverID,
		"method":              in.Method,
		"scheme":              in.Scheme,
		"host":                in.Host,
		"redacted_path":       in.RedactedPath,
		"auth_binding_id":     in.AuthBindingID,
		"fingerprint_version": in.FingerprintVersion,
		"hmac_key_id":         in.HMACKeyID,
		"request_fingerprint": in.RequestFingerprint,
	} {
		if value == "" {
			return fmt.Errorf("%w: missing %s", ErrHITLOperationStoreInvalid, name)
		}
	}
	if !isKnownHITLOperationState(in.State) {
		return fmt.Errorf("%w: unknown state %q", ErrHITLOperationStoreInvalid, in.State)
	}
	if in.CreatedAt.IsZero() || in.SyncWaitDeadline.IsZero() || in.ApprovalExpiresAt.IsZero() {
		return fmt.Errorf("%w: missing operation timestamps", ErrHITLOperationStoreInvalid)
	}
	return nil
}

func isKnownHITLOperationState(state HITLOperationState) bool {
	switch state {
	case HITLOperationStateSyncWaiting,
		HITLOperationStatePendingApproval,
		HITLOperationStateApprovedWaitingForRetry,
		HITLOperationStateDenied,
		HITLOperationStateExpired,
		HITLOperationStateExecutingUpstream,
		HITLOperationStateUpstreamSucceeded,
		HITLOperationStateUpstreamFailed,
		HITLOperationStateClientDisconnected:
		return true
	default:
		return false
	}
}

func isTerminalHITLOperationState(state HITLOperationState) bool {
	switch state {
	case HITLOperationStateDenied, HITLOperationStateExpired, HITLOperationStateUpstreamSucceeded, HITLOperationStateUpstreamFailed, HITLOperationStateClientDisconnected:
		return true
	default:
		return false
	}
}

func timeNS(t time.Time) int64 {
	return t.UTC().UnixNano()
}

func nullTimeNS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return timeNS(t)
}

func timeFromNS(ns int64) time.Time {
	return time.Unix(0, ns).UTC()
}

func nullTimeFromNS(ns sql.NullInt64) *time.Time {
	if !ns.Valid {
		return nil
	}
	t := timeFromNS(ns.Int64)
	return &t
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
