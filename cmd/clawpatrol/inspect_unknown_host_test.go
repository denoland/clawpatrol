package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// Representative package-manager deny CEL for https.unknown (npm / PyPI /
// Go / NuGet / Maven / Docker / crates / RubyGems / Composer / Pub /
// conda / deb / rpm / apk + GitHub archive/release). Header names are
// Go CanonicalMIMEHeaderKey (X-Nuget-Client-Version). Keep aligned with
// Binary Lockdown inspectPackageDenyCel().
const inspectGoldCEL = `('Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/vnd.npm.install-v1+json'))) || ` +
	`('Pacote-Req-Type' in http.headers && size(http.headers['Pacote-Req-Type']) > 0) || ` +
	`('Npm-Command' in http.headers && size(http.headers['Npm-Command']) > 0) || ` +
	`(http.path.contains('/-/') && http.path.endsWith('.tgz')) || ` +
	`('Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/vnd.pypi.simple'))) || ` +
	`(http.path.contains('/@v/list')) || ` +
	`(http.path.endsWith('/@latest')) || ` +
	`(http.path.contains('/@v/') && http.path.endsWith('.info')) || ` +
	`(http.path.contains('/@v/') && http.path.endsWith('.mod')) || ` +
	`(http.path.contains('/@v/') && http.path.endsWith('.zip')) || ` +
	`('X-Nuget-Client-Version' in http.headers && size(http.headers['X-Nuget-Client-Version']) > 0) || ` +
	`(http.path.contains('/v3-flatcontainer/')) || ` +
	`(http.path.contains('/api/v2/package/')) || ` +
	`(http.path.contains('maven-metadata.xml')) || ` +
	`(http.path.endsWith('/ivy.xml')) || ` +
	`(http.path.matches('^/.+/.+/.+/.+[.]pom$')) || ` +
	`(http.path.matches('^/.+/.+/.+/.+[.]jar$')) || ` +
	`(http.path.matches('^/.+/.+/.+/.+[.]war$')) || ` +
	`(http.path.matches('^/.+/.+/.+/.+[.]aar$')) || ` +
	`(http.path.matches('^/.+/.+/.+/.+[.]module$')) || ` +
	`('Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/vnd.oci.image'))) || ` +
	`('Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/vnd.docker.distribution.manifest'))) || ` +
	`(http.path.contains('/v2/') && http.path.contains('/manifests/')) || ` +
	`(http.path.contains('/v2/') && http.path.contains('/blobs/sha256:')) || ` +
	`(http.path.contains('/api/v1/crates/') && http.path.endsWith('/download')) || ` +
	`(http.path.contains('/api/v1/crates/') && http.path.endsWith('.crate')) || ` +
	`(http.path.contains('specs.4.8.gz')) || ` +
	`(http.path.contains('/gems/') && http.path.endsWith('.gem')) || ` +
	`(http.path.matches('^/p2/[^/]+/[^/]+[.]json$')) || ` +
	`('Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/vnd.pub.v2+json'))) || ` +
	`(http.path.matches('/tarballs/[^/]+-[^/]+[.]tar$')) || ` +
	`(http.path.endsWith('/repodata.json')) || ` +
	`(http.path.endsWith('/repodata.json.zst')) || ` +
	`(http.path.contains('/tarballs/') && http.path.endsWith('.conda')) || ` +
	`(http.path.endsWith('.podspec.json')) || ` +
	`(http.path.contains('/dists/') && http.path.endsWith('/InRelease')) || ` +
	`(http.path.contains('/dists/') && http.path.endsWith('/Packages.gz')) || ` +
	`(http.path.contains('/dists/') && http.path.endsWith('/Packages.xz')) || ` +
	`(http.path.endsWith('/repomd.xml')) || ` +
	`(http.path.endsWith('APKINDEX.tar.gz')) || ` +
	`(http.path.contains('/releases/download/')) || ` +
	`(http.path.contains('/archive/refs/')) || ` +
	`(http.path.contains('/tarball/')) || ` +
	`(http.path.contains('/zipball/')) || ` +
	`(http.path.contains('/tar.gz/')) || ` +
	`(http.path.contains('/archive/') && (http.path.endsWith('.zip') || http.path.endsWith('.tar.gz'))) || ` +
	`(http.path.contains('/releases/assets/') && 'Accept' in http.headers && http.headers['Accept'].exists(v, v.contains('application/octet-stream')))`

// Signed-URL / filestore allow CEL. Keep aligned with Binary Lockdown
// cloudStorageRedirectCel().
const cloudStorageRedirectCEL = `(http.path.contains('/filestore/')) || ` +
	`('X-Amz-Signature' in http.query && size(http.query['X-Amz-Signature']) > 0 && 'X-Amz-Algorithm' in http.query && size(http.query['X-Amz-Algorithm']) > 0 && 'X-Amz-Credential' in http.query && size(http.query['X-Amz-Credential']) > 0) || ` +
	`('X-Goog-Signature' in http.query && size(http.query['X-Goog-Signature']) > 0 && 'X-Goog-Algorithm' in http.query && size(http.query['X-Goog-Algorithm']) > 0) || ` +
	`('sv' in http.query && size(http.query['sv']) > 0 && 'sig' in http.query && size(http.query['sig']) > 0 && 'se' in http.query && size(http.query['se']) > 0) || ` +
	`('Key-Pair-Id' in http.query && size(http.query['Key-Pair-Id']) > 0 && 'Signature' in http.query && size(http.query['Signature']) > 0 && ('Expires' in http.query && size(http.query['Expires']) > 0 || 'Policy' in http.query && size(http.query['Policy']) > 0))`

type inspectHdr struct {
	key, value string
}

func TestInspectUnknownHostPackageManagers(t *testing.T) {
	policyHCL := fmt.Sprintf(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

defaults { unknown_host = "inspect" }

endpoint "https" "unknown" { hosts = [] }

rule "allow-unknown-redirect" {
  endpoint  = https.unknown
  priority  = 200
  condition = "%s"
  verdict   = "allow"
  reason    = "cloud storage redirect"
}

rule "deny-unknown-packages" {
  endpoint  = https.unknown
  priority  = 100
  condition = "%s"
  verdict   = "deny"
  reason    = "package resolve"
}

rule "allow-unknown" {
  endpoint  = https.unknown
  priority  = -100
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [] }
`, cloudStorageRedirectCEL, inspectGoldCEL)

	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	gw, diags := config.LoadBytes([]byte(policyHCL), "inspect-unknown-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.UnknownInspect
	if ep == nil {
		t.Fatal("missing UnknownInspect")
	}

	var sawUpstream []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUpstream = append(sawUpstream, r.Host+r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page-ok"))
	}))
	t.Cleanup(upstream.Close)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstream.Listener.Addr().String())
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(transport.CloseIdleConnections)

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { close(sink.ch) })

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{
		db:      db,
		certs:   certs,
		sink:    sink,
		hitl:    newHITLRegistry(sink),
		secrets: newGatewaySecretStore(db, nil),
		onboard: newOnboardRegistry(),
	}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, transport)

	cases := []struct {
		name    string
		host    string
		path    string
		headers []inspectHdr
		deny    bool
	}{
		{name: "page", host: "dsfsdfsdfsdfds.com", path: "/", deny: false},
		{name: "jira", host: "jira.internal", path: "/browse/DOCD-1", deny: false},
		{name: "git upload", host: "git.internal", path: "/org/repo.git/info/refs?service=git-upload-pack", deny: false},
		{name: "blog tgz", host: "dsfsdfsdfsdfds.com", path: "/blog/thing.tgz", deny: false},
		{name: "pypi html simple", host: "pypi-mirror.internal", path: "/simple/requests/", headers: []inspectHdr{{"Accept", "text/html"}}, deny: false},
		{name: "nuget index only", host: "api.internal", path: "/v3/index.json", deny: false},
		{name: "lone jar", host: "files.internal", path: "/files/app.jar", deny: false},
		{name: "helm index", host: "charts.internal", path: "/index.yaml", deny: false},
		{name: "github json asset", host: "git.internal", path: "/repos/cli/cli/releases/assets/123", headers: []inspectHdr{{"Accept", "application/vnd.github+json"}}, deny: false},
		{name: "mcp", host: "mcp.figma.com", path: "/mcp", headers: []inspectHdr{{"Accept", "application/json"}}, deny: false},
		{name: "composer other json", host: "api.internal", path: "/p2/health.json", deny: false},
		{name: "pub html", host: "pub.internal", path: "/api/packages/http", headers: []inspectHdr{{"Accept", "text/html"}}, deny: false},
		{name: "generic tar", host: "files.internal", path: "/tarballs/notes.tar", deny: false},
		{name: "conda notes", host: "files.internal", path: "/notes.conda", deny: false},
		{name: "apt InRelease without dists", host: "docs.internal", path: "/blog/InRelease", deny: false},
		{name: "android apk", host: "files.internal", path: "/app.apk", deny: false},
		{name: "packages.json", host: "api.internal", path: "/packages.json", deny: false},
		{name: "s3 signed npm tarball", host: "jpd-filestore.s3.us-east-1.amazonaws.com", path: "/left-pad/-/left-pad-1.3.0.tgz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID/20260903/us-east-1/s3/aws4_request&X-Amz-Signature=deadbeef", deny: false},
		{name: "azure sas maven", host: "jpd.blob.core.windows.net", path: "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar?sv=2021-08-06&se=2026-09-04T00:00:00Z&sig=abc", deny: false},
		{name: "gcs signed docker", host: "storage.googleapis.com", path: "/v2/library/alpine/blobs/sha256:abc?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature=abc", deny: false},
		{name: "r2 signed cargo", host: "jpd.r2.cloudflarestorage.com", path: "/api/v1/crates/serde/1.0.210/download?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID/20260903/auto/s3/aws4_request&X-Amz-Signature=deadbeef", deny: false},
		{name: "cloudfront key pair", host: "d111111abcdef8.cloudfront.net", path: "/artifactory/npm/left-pad/-/left-pad-1.3.0.tgz?Key-Pair-Id=KEXAMPLE&Signature=sig&Expires=1999999999", deny: false},
		{name: "filestore hash", host: "d111111abcdef8.cloudfront.net", path: "/filestore/ab/cd/abcdef0123456789", deny: false},
		{name: "custom cdn signed gem", host: "cdn.customer.internal", path: "/gems/rake-13.2.1.gem?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID/20260903/auto/s3/aws4_request&X-Amz-Signature=deadbeef", deny: false},
		{name: "docs archive year", host: "docs.internal", path: "/blog/archive/2024/", deny: false},
		{name: "github archive zip", host: "git.internal", path: "/cli/cli/archive/master.zip", deny: true},
		{name: "fake amz algorithm", host: "mirror.internal", path: "/left-pad/-/left-pad-1.3.0.tgz?X-Amz-Algorithm=1", deny: true},

		{name: "npm tarball", host: "dsfsdfsdfsdfds.com", path: "/left-pad/-/left-pad-1.3.0.tgz", deny: true},
		{name: "npm Accept", host: "npm-mirror.internal", path: "/lodash", headers: []inspectHdr{{"Accept", "application/vnd.npm.install-v1+json"}}, deny: true},
		{name: "npm pacote", host: "yarn-mirror.internal", path: "/lodash", headers: []inspectHdr{{"Pacote-Req-Type", "packument"}}, deny: true},
		{name: "npm-command", host: "pnpm-mirror.internal", path: "/lodash", headers: []inspectHdr{{"Npm-Command", "install"}}, deny: true},
		{name: "pypi Accept", host: "pypi-mirror.internal", path: "/simple/requests/", headers: []inspectHdr{{"Accept", "application/vnd.pypi.simple.v1+json"}}, deny: true},
		{name: "go list", host: "goproxy.internal", path: "/rsc.io/quote/@v/list", deny: true},
		{name: "go latest", host: "goproxy.internal", path: "/rsc.io/quote/@latest", deny: true},
		{name: "go info", host: "goproxy.internal", path: "/rsc.io/quote/@v/v1.5.2.info", deny: true},
		{name: "go mod", host: "goproxy.internal", path: "/rsc.io/quote/@v/v1.5.2.mod", deny: true},
		{name: "go zip", host: "goproxy.internal", path: "/rsc.io/quote/@v/v1.5.2.zip", deny: true},
		{name: "nuget client", host: "nuget.internal", path: "/v3/index.json", headers: []inspectHdr{{"X-NuGet-Client-Version", "6.11.0"}}, deny: true},
		{name: "nuget flatcontainer", host: "nuget.internal", path: "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", deny: true},
		{name: "nuget v2", host: "nuget.internal", path: "/api/v2/package/Newtonsoft.Json/13.0.3", deny: true},
		{name: "maven metadata", host: "maven.internal", path: "/com/google/guava/guava/maven-metadata.xml", deny: true},
		{name: "maven pom", host: "maven.internal", path: "/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom", deny: true},
		{name: "maven jar", host: "maven.internal", path: "/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar", deny: true},
		{name: "maven war", host: "maven.internal", path: "/com/example/app/1.0.0/app-1.0.0.war", deny: true},
		{name: "maven aar", host: "maven.internal", path: "/com/example/lib/1.0.0/lib-1.0.0.aar", deny: true},
		{name: "gradle module", host: "maven.internal", path: "/com/google/guava/guava/31.1-jre/guava-31.1-jre.module", deny: true},
		{name: "ivy xml", host: "ivy.internal", path: "/com/google/guava/guava/31.1-jre/ivy.xml", deny: true},
		{name: "docker manifest", host: "registry.internal", path: "/v2/library/alpine/manifests/latest", headers: []inspectHdr{{"Accept", "application/vnd.docker.distribution.manifest.v2+json"}}, deny: true},
		{name: "oci blob", host: "registry.internal", path: "/v2/library/alpine/blobs/sha256:abc", deny: true},
		{name: "cargo download", host: "crates.internal", path: "/api/v1/crates/serde/1.0.210/download", deny: true},
		{name: "rubygems gem", host: "gems.internal", path: "/gems/rake-13.2.1.gem", deny: true},
		{name: "rubygems specs", host: "gems.internal", path: "/specs.4.8.gz", deny: true},
		{name: "composer p2", host: "packagist.internal", path: "/p2/monolog/monolog.json", deny: true},
		{name: "pub Accept", host: "pub.internal", path: "/api/packages/http", headers: []inspectHdr{{"Accept", "application/vnd.pub.v2+json"}}, deny: true},
		{name: "hex tarball", host: "hex.internal", path: "/tarballs/decimal-2.1.0.tar", deny: true},
		{name: "conda repodata", host: "conda.internal", path: "/conda-forge/linux-64/repodata.json", deny: true},
		{name: "conda package", host: "conda.internal", path: "/tarballs/numpy-1.26.4.conda", deny: true},
		{name: "cocoapods spec", host: "cdn.internal", path: "/Specs/a/b/c/Alamofire/5.9.1/Alamofire.podspec.json", deny: true},
		{name: "apt InRelease", host: "deb.internal", path: "/ubuntu/dists/jammy/InRelease", deny: true},
		{name: "apt Packages.gz", host: "deb.internal", path: "/ubuntu/dists/jammy/main/binary-amd64/Packages.gz", deny: true},
		{name: "yum repomd", host: "yum.internal", path: "/centos/8/BaseOS/x86_64/os/repodata/repomd.xml", deny: true},
		{name: "alpine index", host: "apk.internal", path: "/alpine/v3.20/main/x86_64/APKINDEX.tar.gz", deny: true},
		{name: "github release", host: "git.internal", path: "/cli/cli/releases/download/v2.50.0/gh.tar.gz", deny: true},
		{name: "github archive", host: "git.internal", path: "/cli/cli/archive/refs/tags/v2.50.0.tar.gz", deny: true},
		{name: "github asset octet", host: "git.internal", path: "/repos/cli/cli/releases/assets/123", headers: []inspectHdr{{"Accept", "application/octet-stream"}}, deny: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(sawUpstream)
			resp := inspectUnknownSend(t, g, tc.host, tc.path, tc.headers)
			if tc.deny {
				if resp.status != http.StatusForbidden {
					t.Fatalf("status = %d body %q, want 403", resp.status, resp.body)
				}
				if len(sawUpstream) != before {
					t.Fatalf("deny leaked to upstream: %v", sawUpstream[before:])
				}
				return
			}
			if resp.status != http.StatusOK {
				t.Fatalf("status = %d body %q, want 200", resp.status, resp.body)
			}
			if !strings.Contains(resp.body, "page-ok") {
				t.Fatalf("body = %q, want upstream page", resp.body)
			}
		})
	}
}

func inspectUnknownSend(t *testing.T, g *Gateway, host, path string, headers []inspectHdr) credentialMatchResponse {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	g.onboard.profileByIP[peerIP(serverConn)] = "default"
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handle(serverConn, "", 443)
	}()

	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("inspect handshake %s %s: %v", host, path, err)
	}

	rawURL := "https://" + host + path
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, h := range headers {
		req.Header.Set(h.key, h.value)
	}
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	// Close the raw pipe first. tls.Conn.Close sends close-notify and
	// deadlocks on net.Pipe if handle() is blocked in ReadRequest.
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return credentialMatchResponse{status: resp.StatusCode, body: string(body)}
}
