package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	hitlFingerprintHMACBlobKind = "hitl_fingerprint_hmac"
	hitlFingerprintHMACKeyIDV1  = "hitl-hmac:v1"
)

type hitlAsyncGrantRuntime interface {
	HITLAsyncGrantEnabled() bool
	HITLSyncWaitTimeout() time.Duration
	HITLAsyncApprovalTTL() time.Duration
	HITLAsyncApprovedRetryTTL() time.Duration
	HITLAsyncMaxBodyBytes() int64
	HITLAsyncFingerprintBody() string
}

type hitlAsyncOperationInput struct {
	ProfileID   string
	PrincipalID string
	Endpoint    *config.CompiledEndpoint
	Rule        *config.CompiledRule
	ApproverID  string
	Approver    hitlAsyncGrantRuntime
	MatchReq    *match.Request
	HTTPRequest *http.Request
	RawBody     []byte
	Truncated   bool
	Now         time.Time
}

type hitlAsyncOperationStart struct {
	Operation       HITLOperation
	SyncWaitTimeout time.Duration
}

func (g *Gateway) asyncHumanApproverFor(stages []config.ApproveStage) (string, hitlAsyncGrantRuntime, bool) {
	if len(stages) != 1 || stages[0].Name == "dashboard" {
		return "", nil, false
	}
	policy := g.Policy()
	if policy == nil {
		return "", nil, false
	}
	ent := policy.Approvers[stages[0].Name]
	if ent == nil {
		return "", nil, false
	}
	rt, ok := ent.Body.(hitlAsyncGrantRuntime)
	if !ok || !rt.HITLAsyncGrantEnabled() {
		return "", nil, false
	}
	return stages[0].Name, rt, true
}

func (g *Gateway) maybeStartAsyncHITLOperation(ctx context.Context, in hitlAsyncOperationInput) (hitlAsyncOperationStart, bool, error) {
	if g == nil || g.db == nil || g.cfg == nil || g.cfg.PublicURL == "" || in.HTTPRequest == nil || in.Endpoint == nil || in.Rule == nil || in.Approver == nil {
		return hitlAsyncOperationStart{}, false, nil
	}
	if in.ProfileID == "" || in.PrincipalID == "" || in.ApproverID == "" || in.MatchReq == nil {
		return hitlAsyncOperationStart{}, false, nil
	}
	policy := g.Policy()
	if policy == nil || policy.Profiles[in.ProfileID] == nil || !policy.Profiles[in.ProfileID].HITLAsyncGrants || !in.Approver.HITLAsyncGrantEnabled() {
		return hitlAsyncOperationStart{}, false, nil
	}
	syncWait := in.Approver.HITLSyncWaitTimeout()
	if syncWait <= 0 {
		return hitlAsyncOperationStart{}, false, nil
	}
	if in.Approver.HITLAsyncFingerprintBody() != config.HITLAsyncFingerprintRawBody || in.Truncated || int64(len(in.RawBody)) > in.Approver.HITLAsyncMaxBodyBytes() {
		return hitlAsyncOperationStart{}, false, nil
	}
	key, err := loadOrCreateHITLFingerprintKey(ctx, g.db)
	if err != nil {
		return hitlAsyncOperationStart{}, false, err
	}
	cc := runtime.ResolveCredential(in.Endpoint, in.MatchReq)
	authBindingID, err := buildHITLAuthBindingID(ctx, g.db, in.ProfileID, cc)
	if err != nil {
		return hitlAsyncOperationStart{}, false, err
	}
	selectedHeaders, err := SelectHITLFingerprintHeaders(in.HTTPRequest.Header, nil)
	if err != nil {
		return hitlAsyncOperationStart{}, false, err
	}
	fp, err := ComputeHITLRequestFingerprint(HITLRequestFingerprintInput{
		Key:             key,
		ProfileID:       in.ProfileID,
		PrincipalID:     in.PrincipalID,
		EndpointID:      in.Endpoint.Name,
		ApprovalRuleID:  in.Rule.Name,
		Method:          in.HTTPRequest.Method,
		Scheme:          "https",
		Host:            in.HTTPRequest.Host,
		Path:            in.HTTPRequest.URL.Path,
		RawQuery:        in.HTTPRequest.URL.RawQuery,
		SelectedHeaders: selectedHeaders,
		RawBody:         in.RawBody,
		AuthBindingID:   authBindingID,
	})
	if err != nil {
		return hitlAsyncOperationStart{}, false, err
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	redactedHeadersJSON := ""
	if len(selectedHeaders) > 0 {
		if b, err := json.Marshal(selectedHeaders); err == nil {
			redactedHeadersJSON = string(b)
		}
	}
	op, err := NewHITLOperationStore(g.db).Create(ctx, HITLOperationCreate{
		State:               HITLOperationStateSyncWaiting,
		ProfileID:           in.ProfileID,
		PrincipalID:         in.PrincipalID,
		EndpointID:          in.Endpoint.Name,
		ApprovalRuleID:      in.Rule.Name,
		ApproverID:          in.ApproverID,
		Method:              in.HTTPRequest.Method,
		Scheme:              "https",
		Host:                in.HTTPRequest.Host,
		RedactedPath:        in.HTTPRequest.URL.EscapedPath(),
		RedactedQuery:       "",
		RedactedHeadersJSON: redactedHeadersJSON,
		AuthBindingID:       authBindingID,
		FingerprintVersion:  fp.Version,
		HMACKeyID:           fp.HMACKeyID,
		RequestFingerprint:  fp.RequestFingerprint,
		CreatedAt:           now,
		SyncWaitDeadline:    now.Add(syncWait),
		ApprovalExpiresAt:   now.Add(in.Approver.HITLAsyncApprovalTTL()),
		RetryExpiresAt:      now.Add(in.Approver.HITLAsyncApprovedRetryTTL()),
	})
	if err != nil {
		return hitlAsyncOperationStart{}, false, err
	}
	return hitlAsyncOperationStart{Operation: op, SyncWaitTimeout: syncWait}, true, nil
}

func (g *Gateway) transitionAsyncHITLOperation(ctx context.Context, op HITLOperation, to HITLOperationState, lastErr string) (HITLOperation, error) {
	if g == nil || g.db == nil || op.ID == "" {
		return op, nil
	}
	updated, err := NewHITLOperationStore(g.db).Transition(ctx, HITLOperationTransition{
		ID:              op.ID,
		FromState:       op.State,
		ToState:         to,
		ExpectedVersion: op.Version,
		Now:             time.Now().UTC(),
		LastError:       lastErr,
	})
	if err != nil {
		return HITLOperation{}, err
	}
	g.updateHITLOperationMessage(context.Background(), updated)
	return updated, nil
}

func (g *Gateway) recordHITLOperationMessageRef(ctx context.Context, operationID, ref string) error {
	if g == nil || g.db == nil || operationID == "" || ref == "" {
		return nil
	}
	op, err := NewHITLOperationStore(g.db).SetApproverMessageRef(ctx, operationID, ref)
	if err != nil {
		return err
	}
	if op.State != HITLOperationStateSyncWaiting {
		g.updateHITLOperationMessage(context.Background(), op)
	}
	return nil
}

func (g *Gateway) updateHITLOperationMessage(ctx context.Context, op HITLOperation) {
	if g == nil || op.ID == "" || op.ApproverMessageRef == "" {
		return
	}
	policy := g.Policy()
	if policy == nil {
		return
	}
	approver := policy.Approvers[op.ApproverID]
	if approver == nil {
		return
	}
	credName := ""
	if h, ok := approver.Body.(runtime.HITLHumanCredentialer); ok {
		credName = h.HumanApproverCredential()
	}
	if credName == "" {
		return
	}
	cred := policy.Credentials[credName]
	if cred == nil {
		return
	}
	updater, ok := cred.Body.(runtime.HITLMessageUpdater)
	if !ok {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := updater.UpdateHITLMessage(ctx, g.secrets, runtime.HITLMessageUpdate{
		MessageRef:     op.ApproverMessageRef,
		OperationID:    op.ID,
		State:          runtime.HITLOperationState(op.State),
		Method:         op.Method,
		Host:           op.Host,
		Path:           op.RedactedPath,
		Profile:        op.ProfileID,
		UpstreamCalled: op.UpstreamCalled,
		LastError:      op.LastError,
	}); err != nil {
		log.Printf("hitl async operation message update %s: %v", op.ID, err)
	}
}

func (g *Gateway) resolveAsyncHITLGrant(operationID string, d runtime.HITLDecision) runtime.HITLResolveResult {
	if g == nil || g.db == nil {
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "async HITL operation store is unavailable"}
	}
	store := NewHITLOperationStore(g.db)
	op, err := store.get(context.Background(), operationID)
	if errors.Is(err, ErrHITLOperationNotFound) {
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "async HITL operation not found"}
	}
	if err != nil {
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: "load async HITL operation"}
	}
	to := HITLOperationStateDenied
	state := runtime.HITLStateDenied
	reason := "denied by approver"
	tr := HITLOperationTransition{
		ID:              op.ID,
		FromState:       op.State,
		ExpectedVersion: op.Version,
		Now:             time.Now().UTC(),
	}
	if d.Allow {
		to = HITLOperationStateApprovedWaitingForRetry
		state = runtime.HITLStateApproved
		reason = "approved; waiting for matching client retry"
		if op.RetryExpiresAt != nil {
			tr.RetryExpiresAt = *op.RetryExpiresAt
		}
		if !tr.RetryExpiresAt.After(tr.Now) {
			tr.RetryExpiresAt = tr.Now.Add(config.HITLAsyncDefaultApprovedRetryTTL)
		}
	} else if d.Reason != "" {
		reason = d.Reason
	}
	tr.ToState = to
	updated, err := store.Transition(context.Background(), tr)
	if err != nil {
		return runtime.HITLResolveResult{OK: false, State: runtime.HITLStateUnknown, Reason: err.Error()}
	}
	g.updateHITLOperationMessage(context.Background(), updated)
	return runtime.HITLResolveResult{OK: true, State: state, Reason: reason}
}

func loadOrCreateHITLFingerprintKey(ctx context.Context, db *sql.DB) (HITLFingerprintKey, error) {
	if db == nil {
		return HITLFingerprintKey{}, fmt.Errorf("%w: nil db", ErrHITLFingerprintInvalid)
	}
	key, ok, err := getHITLFingerprintKey(ctx, db)
	if err != nil || ok {
		return key, err
	}
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		return HITLFingerprintKey{}, fmt.Errorf("generate hitl fingerprint key: %w", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO gateway_blobs (kind, name, value, updated_ns) VALUES (?, ?, ?, ?)`, hitlFingerprintHMACBlobKind, hitlFingerprintHMACKeyIDV1, root, time.Now().UnixNano())
	if err != nil {
		if key, ok, getErr := getHITLFingerprintKey(ctx, db); getErr != nil {
			return HITLFingerprintKey{}, err
		} else if ok {
			return key, nil
		}
		return HITLFingerprintKey{}, err
	}
	return HITLFingerprintKey{ID: hitlFingerprintHMACKeyIDV1, Root: root}, nil
}

func getHITLFingerprintKey(ctx context.Context, db *sql.DB) (HITLFingerprintKey, bool, error) {
	var root []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM gateway_blobs WHERE kind = ? AND name = ?`, hitlFingerprintHMACBlobKind, hitlFingerprintHMACKeyIDV1).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return HITLFingerprintKey{}, false, nil
	}
	if err != nil {
		return HITLFingerprintKey{}, false, err
	}
	return HITLFingerprintKey{ID: hitlFingerprintHMACKeyIDV1, Root: root}, true, nil
}

func buildHITLAuthBindingID(ctx context.Context, db *sql.DB, profileID string, cc *config.CompiledCredential) (string, error) {
	credentialID := "none"
	generation := "none"
	if cc != nil && cc.Credential != nil && cc.Credential.Symbol != nil {
		credentialID = cc.Credential.Symbol.Name
		gen, err := hitlCredentialGeneration(ctx, db, credentialID)
		if err != nil {
			return "", err
		}
		generation = gen
	}
	return BuildHITLCredentialAuthBindingID(HITLCredentialAuthBindingInput{ProfileID: profileID, CredentialID: credentialID, Generation: generation})
}

func hitlCredentialGeneration(ctx context.Context, db *sql.DB, credentialID string) (string, error) {
	if db == nil {
		return "env-or-empty:" + credentialID, nil
	}
	var secretNS sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(updated_ns) FROM credential_secrets WHERE credential = ?`, credentialID).Scan(&secretNS); err != nil {
		return "", err
	}
	if secretNS.Valid && secretNS.Int64 > 0 {
		return fmt.Sprintf("credential-secret:%d", secretNS.Int64), nil
	}
	var oauthNS sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(updated_ns) FROM credentials WHERE id = ?`, credentialID).Scan(&oauthNS); err != nil {
		return "", err
	}
	if oauthNS.Valid && oauthNS.Int64 > 0 {
		return fmt.Sprintf("oauth-credential:%d", oauthNS.Int64), nil
	}
	return "env-or-empty:" + credentialID, nil
}

func writeHITLOperationAcceptedToConn(w io.Writer, op HITLOperation, publicURL string) {
	if w == nil {
		return
	}
	rr := httptest.NewRecorder()
	writeHITLOperationAccepted(rr, op, publicURL)
	resp := rr.Result()
	defer func() { _ = resp.Body.Close() }()
	resp.ContentLength = int64(rr.Body.Len())
	resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	_ = resp.Write(w)
}

func hitlAsyncFailureReason(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}
