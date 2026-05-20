package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/match"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const hitlRetryMismatchErrorValue = "hitl_retry_mismatch"

type hitlRetryRelayInput struct {
	OperationID string
	ProfileID   string
	PrincipalID string
	Endpoint    *config.CompiledEndpoint
	Rule        *config.CompiledRule
	MatchReq    *match.Request
	HTTPRequest *http.Request
	RawBody     []byte
	Truncated   bool
}

func (g *Gateway) consumeHITLRetryGrantForRequest(ctx context.Context, in hitlRetryRelayInput) (HITLOperation, error) {
	if in.OperationID == "" {
		return HITLOperation{}, fmt.Errorf("%w: missing retry operation id", ErrHITLRetryMismatch)
	}
	if in.Endpoint == nil || in.Rule == nil || in.HTTPRequest == nil {
		return HITLOperation{}, fmt.Errorf("%w: retry request no longer matches the approved endpoint/rule", ErrHITLRetryMismatch)
	}
	if in.Truncated {
		return HITLOperation{}, fmt.Errorf("%w: retry request body is not fully fingerprintable", ErrHITLRetryMismatch)
	}
	key, err := loadOrCreateHITLFingerprintKey(ctx, g.db)
	if err != nil {
		return HITLOperation{}, err
	}
	cc := runtime.ResolveCredential(g.Policy(), in.ProfileID, in.Endpoint, in.MatchReq)
	authBindingID, err := buildHITLAuthBindingID(ctx, g.db, in.ProfileID, cc)
	if err != nil {
		return HITLOperation{}, err
	}
	fp, err := ComputeHITLRequestFingerprint(HITLRequestFingerprintInput{
		Key:            key,
		ProfileID:      in.ProfileID,
		PrincipalID:    in.PrincipalID,
		EndpointID:     in.Endpoint.Name,
		ApprovalRuleID: in.Rule.Name,
		Method:         in.HTTPRequest.Method,
		Scheme:         "https",
		Host:           in.HTTPRequest.Host,
		Path:           in.HTTPRequest.URL.Path,
		RawQuery:       in.HTTPRequest.URL.RawQuery,
		RawBody:        in.RawBody,
		AuthBindingID:  authBindingID,
	})
	if err != nil {
		return HITLOperation{}, err
	}
	return NewHITLOperationStore(g.db).ConsumeRetryGrant(ctx, HITLRetryGrantConsume{
		ID:                 in.OperationID,
		ProfileID:          in.ProfileID,
		PrincipalID:        in.PrincipalID,
		AuthBindingID:      authBindingID,
		FingerprintVersion: fp.Version,
		HMACKeyID:          fp.HMACKeyID,
		RequestFingerprint: fp.RequestFingerprint,
		ConsumedBy:         in.PrincipalID,
		Now:                time.Now().UTC(),
	})
}

func (g *Gateway) transitionConsumedHITLRetryGrant(ctx context.Context, op HITLOperation, to HITLOperationState, lastErr string) error {
	if g == nil || g.db == nil || op.ID == "" {
		return nil
	}
	if op.State != HITLOperationStateExecutingUpstream {
		return nil
	}
	updated, err := NewHITLOperationStore(g.db).Transition(ctx, HITLOperationTransition{
		ID:              op.ID,
		FromState:       op.State,
		ToState:         to,
		ExpectedVersion: op.Version,
		Now:             time.Now().UTC(),
		UpstreamCalled:  true,
		LastError:       lastErr,
	})
	if err != nil {
		return err
	}
	g.updateHITLOperationMessage(context.Background(), updated)
	return nil
}

func hitlRetryRelayFailure(statusErr error) (status int, contentType string, body string) {
	if errors.Is(statusErr, ErrHITLOperationNotFound) {
		return http.StatusNotFound, "application/json", fmt.Sprintf("{\"error\":%q}\n", hitlOperationNotFoundErrorValue)
	}
	return http.StatusConflict, "application/json", fmt.Sprintf("{\"error\":%q}\n", hitlRetryMismatchErrorValue)
}
