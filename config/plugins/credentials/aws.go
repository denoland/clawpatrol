package credentials

// aws_credential: static AWS API credentials (access key + secret +
// optional session token). At inject time the gateway SigV4-signs the
// outbound request using the service + region declared on the
// endpoint, so the agent never sees the real credentials. v1 is
// static-only; STS / SSO / IRSA / EC2 metadata flavours are
// follow-ups.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/config"
	"github.com/denoland/clawpatrol/config/runtime"
)

// AWSCredential is part of the clawpatrol plugin API.
//
// Schema is intentionally empty: access key id and secret access key
// (and optional session token) live in the secret store as named
// slots, filled via the dashboard or CLAWPATROL_SECRET_<NAME>_<SLOT>
// env vars. Service + region come from the endpoint at request time.
type AWSCredential struct{}

// awsSigningParams is the contract the AWS endpoint plugin satisfies
// so this credential can read service + region without importing the
// endpoint package (which would be a cycle).
type awsSigningParams interface {
	AWSSigningParams() (service, region string)
}

// SignHTTPRequest is part of the clawpatrol plugin API.
func (*AWSCredential) SignHTTPRequest(_ context.Context, req *http.Request, sec runtime.Secret, endpoint any) error {
	params, ok := endpoint.(awsSigningParams)
	if !ok {
		return errors.New("aws_credential: endpoint does not declare AWS signing params (use `endpoint \"aws\"`)")
	}
	service, region := params.AWSSigningParams()
	if service == "" || region == "" {
		return errors.New("aws_credential: endpoint missing service / region")
	}
	akid, secret, token, err := awsCredentialMaterial(sec)
	if err != nil {
		return err
	}
	return signSigV4(req, sigV4Params{
		AccessKeyID:     akid,
		SecretAccessKey: secret,
		SessionToken:    token,
		Service:         service,
		Region:          region,
		Now:             time.Now(),
	})
}

// awsCredentialMaterial reads the three secret slots. access_key_id
// and secret_access_key are required; session_token is optional
// (present for STS-issued credentials the operator pasted in).
func awsCredentialMaterial(sec runtime.Secret) (akid, secret, token string, err error) {
	akid = sec.Extras["access_key_id"]
	secret = sec.Extras["secret_access_key"]
	token = sec.Extras["session_token"]
	if akid == "" || secret == "" {
		return "", "", "", fmt.Errorf("aws_credential: missing access_key_id / secret_access_key " +
			"(set CLAWPATROL_SECRET_<NAME>_ACCESS_KEY_ID and _SECRET_ACCESS_KEY, or fill the slots in the dashboard)")
	}
	return akid, secret, token, nil
}

// SecretSlots is part of the clawpatrol plugin API.
func (*AWSCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "access_key_id", Label: "AWS access key ID",
			Description: "The 20-char AKIA… / ASIA… identifier."},
		{Name: "secret_access_key", Label: "AWS secret access key",
			Description: "The 40-char secret. Used as the SigV4 signing seed."},
		{Name: "session_token", Label: "AWS session token (optional)",
			Description: "Set only when using STS-issued temporary credentials."},
	}
}

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "aws_credential",
		New:     newer[AWSCredential](),
		Runtime: (*AWSCredential)(nil),
		Build:   passthrough,
		Emit: func(_ any, _ string, _ *hclwrite.Body) {
			// AWSCredential has no HCL attributes — service + region
			// live on the endpoint, not the credential.
		},
	})
}
