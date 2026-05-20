package credentials

// aws_credential: static AWS API credentials (access key + secret +
// optional session token) used to mint an EKS-style bearer token for
// the kubernetes endpoint. At inject time the gateway calls STS
// GetCallerIdentity via aws-sdk-go-v2's presigner with the
// `x-k8s-aws-id` header carrying the cluster name; the presigned URL
// is base64url-encoded as `k8s-aws-v1.<url>` and stamped as the
// upstream Authorization. The agent never sees real credentials.
//
// Only the kubernetes endpoint consumes this credential today. Generic
// SigV4-signed API calls (DynamoDB, S3, etc.) are out of scope.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/hcl/v2/hclwrite"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

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
		return errors.New("aws_credential: endpoint does not declare EKS auth params (use `endpoint \"kubernetes\"` with cluster_name + region)")
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

func init() {
	var _ runtime.HTTPRequestSigner = (*AWSCredential)(nil)
	var _ runtime.EKSBearerMinter = (*AWSCredential)(nil)
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
