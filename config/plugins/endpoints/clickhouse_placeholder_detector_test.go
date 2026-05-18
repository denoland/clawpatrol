package endpoints

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/config/match"
	sqlfacet "github.com/denoland/clawpatrol/config/plugins/facets/sql"
)

// TestClickhouseNativeDetectPlaceholderScansHelloFields confirms the
// detector finds a placeholder substring whether it sat in the
// agent's username or password field. The runtime caller stuffs both
// (joined by NUL) into Meta.Statement before resolving credentials.
func TestClickhouseNativeDetectPlaceholderScansHelloFields(t *testing.T) {
	det := ClickhouseNativeEndpointRuntime{}
	candidates := []string{"PH_ro", "PH_rw"}

	cases := []struct {
		name      string
		statement string
		want      string
	}{
		{"placeholder in username", "PH_ro\x00secret", "PH_ro"},
		{"placeholder in password", "agent\x00PH_rw", "PH_rw"},
		{"no placeholder", "agent\x00secret", ""},
		{"first match wins", "PH_ro\x00PH_rw", "PH_ro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &match.Request{Meta: &sqlfacet.Meta{Statement: tc.statement}}
			if got := det.DetectPlaceholder(req, candidates); got != tc.want {
				t.Errorf("DetectPlaceholder(%q) = %q, want %q", tc.statement, got, tc.want)
			}
		})
	}
}

func TestClickhouseNativeDetectPlaceholderRejectsNonSQLMeta(t *testing.T) {
	det := ClickhouseNativeEndpointRuntime{}
	if got := det.DetectPlaceholder(&match.Request{Meta: "not-a-meta"}, []string{"PH"}); got != "" {
		t.Errorf("expected empty on non-SQL meta, got %q", got)
	}
	if got := det.DetectPlaceholder(nil, []string{"PH"}); got != "" {
		t.Errorf("expected empty on nil request, got %q", got)
	}
}

// TestClickhouseHTTPSDetectPlaceholderCoversAllSlots probes every
// HTTPS slot ClickHouse honors for credentials: Authorization header
// (raw + decoded Basic payload), the X-ClickHouse-User /
// X-ClickHouse-Key headers, and the ?user= / ?password= query params.
func TestClickhouseHTTPSDetectPlaceholderCoversAllSlots(t *testing.T) {
	det := ClickhouseHTTPSEndpointRuntime{}
	candidates := []string{"PH_match"}

	cases := []struct {
		name string
		req  *match.Request
		want string
	}{
		{
			"Authorization header (Bearer)",
			&match.Request{Headers: http.Header{"Authorization": []string{"Bearer PH_match"}}},
			"PH_match",
		},
		{
			"Authorization header (Basic decoded)",
			&match.Request{Headers: http.Header{"Authorization": []string{"Basic UEhfbWF0Y2g6cHc="}}}, // PH_match:pw
			"PH_match",
		},
		{
			"X-ClickHouse-User",
			&match.Request{Headers: http.Header{"X-Clickhouse-User": []string{"PH_match"}}},
			"PH_match",
		},
		{
			"X-ClickHouse-Key",
			&match.Request{Headers: http.Header{"X-Clickhouse-Key": []string{"PH_match"}}},
			"PH_match",
		},
		{
			"query ?user=",
			&match.Request{URL: &url.URL{RawQuery: "user=PH_match"}},
			"PH_match",
		},
		{
			"query ?password=",
			&match.Request{URL: &url.URL{RawQuery: "password=PH_match"}},
			"PH_match",
		},
		{
			"no match anywhere",
			&match.Request{Headers: http.Header{"Authorization": []string{"Bearer something-else"}}},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := det.DetectPlaceholder(tc.req, candidates); got != tc.want {
				t.Errorf("DetectPlaceholder = %q, want %q", got, tc.want)
			}
		})
	}
}
