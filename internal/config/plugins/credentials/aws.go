package credentials

// aws_credential: static AWS API credentials (access key + secret +
// optional session token). Two jobs:
//
//  1. EKS bearer: when bound to a kubernetes endpoint the gateway calls
//     STS GetCallerIdentity via aws-sdk-go-v2's presigner with the
//     `x-k8s-aws-id` header carrying the cluster name; the presigned URL
//     is base64url-encoded as `k8s-aws-v1.<url>` and stamped as the
//     upstream Authorization.
//
//  2. SigV4 re-signing: when bound to a plain `("https" "aws")` endpoint
//     the agent's aws-cli signs the request with injected placeholder
//     creds (see EnvVars); the gateway strips that signature and re-signs
//     with the operator's real stored creds (see reSignProxiedRequest).
//
// Either way the agent never sees real credentials.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// emptyPayloadHash is the SHA-256 of the empty string — the SigV4
// payload hash the signer requires when an incoming request carried no
// X-Amz-Content-Sha256 header to reuse.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// AWSCredential is part of the clawpatrol plugin API.
//
// Schema is intentionally empty: access key id and secret access key
// (and optional session token) live in the secret store as named
// slots, filled via the dashboard or CLAWPATROL_SECRET_<NAME>_<SLOT>
// env vars. Cluster + region come from the kubernetes endpoint at
// request time.
type AWSCredential struct{}

// awsEKSParams is the contract the kubernetes endpoint satisfies so
// this credential can read cluster + region without importing the
// endpoint package (which would be a cycle).
type awsEKSParams interface {
	AWSEKSAuthParams() (cluster, region string)
}

// SignHTTPRequest is part of the clawpatrol plugin API.
func (c *AWSCredential) SignHTTPRequest(ctx context.Context, req *http.Request, sec runtime.Secret, endpoint any) error {
	params, ok := endpoint.(awsEKSParams)
	if !ok {
		// Non-EKS endpoint (a plain `("https" "aws")` upstream): the
		// agent already produced a SigV4 signature with placeholder
		// creds — replace it with one minted from the real stored creds.
		return c.reSignProxiedRequest(ctx, req, sec)
	}
	cluster, region := params.AWSEKSAuthParams()
	if cluster == "" || region == "" {
		return errors.New("aws_credential: kubernetes endpoint missing cluster_name / region")
	}
	bearer, err := c.MintEKSBearer(ctx, sec, region, cluster)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return nil
}

// MintEKSBearer implements runtime.EKSBearerMinter — same code path
// SignHTTPRequest uses, exported so the kubernetes_port_forward
// tunnel can build a self-contained kubeconfig without a parallel
// STS presign.
func (*AWSCredential) MintEKSBearer(ctx context.Context, sec runtime.Secret, region, cluster string) (string, error) {
	if cluster == "" || region == "" {
		return "", errors.New("aws_credential: cluster + region are required to mint an EKS bearer")
	}
	akid, secret, token, err := awsCredentialMaterial(sec)
	if err != nil {
		return "", err
	}
	return mintEKSBearerToken(ctx, akid, secret, token, region, cluster)
}

// reSignProxiedRequest replaces the agent's placeholder-cred SigV4
// signature with one minted from the operator's real stored creds. The
// agent's aws-cli already canonicalized the request (host, x-amz-date,
// x-amz-content-sha256, …); we strip its auth headers and re-sign in
// place so the upstream sees a request signed by real credentials.
func (c *AWSCredential) reSignProxiedRequest(ctx context.Context, req *http.Request, sec runtime.Secret) error {
	akid, secret, token, err := awsCredentialMaterial(sec)
	if err != nil {
		return err
	}

	service, region := awsServiceRegion(req.Header.Get("Authorization"), req.URL.Host)
	if service == "" || region == "" {
		return fmt.Errorf("aws_credential: cannot derive service/region for %q (no SigV4 credential scope and unrecognized host)", req.URL.Host)
	}

	// Reuse the hash the agent already computed and signed over rather
	// than recomputing from the (possibly already-consumed) body.
	payloadHash := req.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = emptyPayloadHash
	}

	// Drop the agent's placeholder signature + any session token it
	// carried; SignHTTP re-stamps Authorization (and X-Amz-Security-Token
	// when our creds are STS-issued).
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Security-Token")

	creds := aws.Credentials{AccessKeyID: akid, SecretAccessKey: secret, SessionToken: token}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, payloadHash, service, region, time.Now()); err != nil {
		return fmt.Errorf("aws_credential: re-sign %s request: %w", service, err)
	}
	return nil
}

// awsServiceRegion derives the SigV4 service + region for re-signing. It
// prefers the credential scope the agent baked into the incoming
// Authorization header (Credential=AKID/<date>/<region>/<service>/aws4_request)
// — exactly what aws-cli computed for this request — and falls back to
// the upstream hostname when that header is absent or unparseable.
func awsServiceRegion(authHeader, host string) (service, region string) {
	if svc, reg := parseSigV4CredentialScope(authHeader); svc != "" && reg != "" {
		return svc, reg
	}
	return serviceRegionFromHost(host)
}

// parseSigV4CredentialScope pulls service + region out of a SigV4
// Authorization header's `Credential=` element. Returns empty strings
// when the header is missing or doesn't match the expected shape.
func parseSigV4CredentialScope(authHeader string) (service, region string) {
	const marker = "Credential="
	i := strings.Index(authHeader, marker)
	if i < 0 {
		return "", ""
	}
	scope := authHeader[i+len(marker):]
	// The scope ends at the first comma or space (SignedHeaders follows).
	if j := strings.IndexAny(scope, ", "); j >= 0 {
		scope = scope[:j]
	}
	// AKID / date / region / service / aws4_request
	parts := strings.Split(scope, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return "", ""
	}
	return parts[3], parts[2]
}

// serviceRegionFromHost recovers service + region from a standard AWS
// endpoint hostname: `service.region.amazonaws.com`, or
// `service.amazonaws.com` for global endpoints (iam, sts, …) which AWS
// treats as us-east-1.
func serviceRegionFromHost(host string) (service, region string) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".amazonaws.com")
	if host == "" {
		return "", ""
	}
	labels := strings.Split(host, ".")
	service = labels[0]
	if len(labels) >= 2 {
		region = labels[len(labels)-1]
		return service, region
	}
	return service, "us-east-1"
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

// mintEKSBearerToken returns the "k8s-aws-v1.<base64url(presigned-url)>"
// bearer EKS accepts on the kubernetes API. The presigned URL is an
// STS GetCallerIdentity request whose canonical signature includes a
// `x-k8s-aws-id` header carrying the cluster name — same wire format
// `aws eks get-token` emits, just generated in-process so we don't
// shell out and don't need ambient AWS creds.
func mintEKSBearerToken(ctx context.Context, akid, secret, sessionToken, region, cluster string) (string, error) {
	cfg := aws.Config{
		Region:      region,
		Credentials: awscreds.NewStaticCredentialsProvider(akid, secret, sessionToken),
	}
	presigner := sts.NewPresignClient(sts.NewFromConfig(cfg), func(o *sts.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(co *sts.Options) {
			co.APIOptions = append(co.APIOptions, eksPresignMiddleware(cluster))
		})
	})
	out, err := presigner.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("aws_credential: presign sts GetCallerIdentity: %w", err)
	}
	return "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(out.URL)), nil
}

// eksPresignMiddleware stamps both the `x-k8s-aws-id` header (so the
// canonical request includes the cluster scope EKS pins) and the
// `X-Amz-Expires=60` query parameter required by aws-iam-authenticator
// before the SigV4 signer reads headers / query to build the canonical
// request. The SDK's PresignHTTP intentionally omits X-Amz-Expires;
// aws-iam-authenticator (and EKS's webhook frontend) reject any
// presigned URL whose query string has no expiration — the request
// then comes back as 401 Unauthorized from the apiserver.
//
// The signer runs in Finalize, so mutating the request in Build
// (After) guarantees both pieces are part of the signature.
func eksPresignMiddleware(cluster string) func(*smithymiddleware.Stack) error {
	return func(stack *smithymiddleware.Stack) error {
		return stack.Build.Add(smithymiddleware.BuildMiddlewareFunc(
			"clawpatrolEKSPresign",
			func(ctx context.Context, in smithymiddleware.BuildInput, next smithymiddleware.BuildHandler) (smithymiddleware.BuildOutput, smithymiddleware.Metadata, error) {
				r, ok := in.Request.(*smithyhttp.Request)
				if !ok {
					return smithymiddleware.BuildOutput{}, smithymiddleware.Metadata{}, fmt.Errorf("aws_credential: unexpected smithy request type %T", in.Request)
				}
				r.Header.Set("X-K8s-Aws-Id", cluster)
				// aws-iam-authenticator caps presigned URL age at
				// 60s; matching aws-cli's `eks get-token` shape.
				q := r.URL.Query()
				q.Set("X-Amz-Expires", "60")
				r.URL.RawQuery = q.Encode()
				return next.HandleBuild(ctx, in)
			},
		), smithymiddleware.After)
	}
}

// SecretSlots is part of the clawpatrol plugin API.
func (*AWSCredential) SecretSlots() []config.SecretSlot {
	return []config.SecretSlot{
		{Name: "access_key_id", Label: "AWS access key ID",
			Description: "The 20-char AKIA… / ASIA… identifier."},
		{Name: "secret_access_key", Label: "AWS secret access key",
			Description: "The 40-char secret. Used as the SigV4 signing seed for the STS presign."},
		{Name: "session_token", Label: "AWS session token (optional)",
			Description: "Set only when using STS-issued temporary credentials."},
	}
}

// EnvVars is part of the clawpatrol plugin API.
//
// Mirrors the Anthropic OAuth credential's pushdown (see
// anthropic_oauth.go): aws-cli and the AWS SDKs read credentials out of
// the process environment, so `clawpatrol env` exports placeholders that
// satisfy local SigV4 signing. The gateway re-signs the proxied request
// with the operator's real stored creds at MITM time (reSignProxiedRequest),
// so these placeholder bytes never authenticate anything upstream.
func (*AWSCredential) EnvVars() []config.EnvVar {
	return []config.EnvVar{
		{Name: "AWS_ACCESS_KEY_ID", Value: phAWSKeyID, Description: "aws-cli / AWS SDKs (placeholder; gateway re-signs)"},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: phAWSSecret, Description: "aws-cli / AWS SDKs (placeholder; gateway re-signs)"},
		{Name: "AWS_DEFAULT_REGION", Value: "us-east-1", Description: "aws-cli default region (overridable per call)"},
	}
}

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSCredential)(nil)
	var _ runtime.EKSBearerMinter = (*AWSCredential)(nil)
	var _ config.EnvPushdownProvider = (*AWSCredential)(nil)
	config.Register(&config.Plugin{
		Kind:    config.KindCredential,
		Type:    "aws_credential",
		New:     newer[AWSCredential](),
		Runtime: (*AWSCredential)(nil),
		Build:   passthrough,
		Emit: func(_ any, _ string, _ *hclwrite.Body) {
			// AWSCredential has no HCL attributes — cluster + region
			// live on the endpoint, not the credential.
		},
	})
}
