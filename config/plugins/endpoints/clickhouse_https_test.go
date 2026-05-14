package endpoints

import (
	"net/http"
	"net/url"
	"testing"
)

// TestClickhouseHTTPSDatabase pins the URL/header extraction order
// for the clickhouse_https `sql.database` facet. ClickHouse accepts
// the target database either as the `database` query parameter or as
// `X-ClickHouse-Database`; the helper honours whichever is present
// and prefers the query parameter when both are set.
func TestClickhouseHTTPSDatabase(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "query parameter",
			req: &http.Request{
				URL: mustParseURL(t, "https://ch.example/?database=foo"),
			},
			want: "foo",
		},
		{
			name: "header",
			req: &http.Request{
				URL:    mustParseURL(t, "https://ch.example/"),
				Header: http.Header{"X-Clickhouse-Database": []string{"bar"}},
			},
			want: "bar",
		},
		{
			name: "query takes precedence over header",
			req: &http.Request{
				URL:    mustParseURL(t, "https://ch.example/?database=fromquery"),
				Header: http.Header{"X-Clickhouse-Database": []string{"fromheader"}},
			},
			want: "fromquery",
		},
		{
			name: "neither set → empty",
			req: &http.Request{
				URL: mustParseURL(t, "https://ch.example/?other=1"),
			},
			want: "",
		},
		{
			name: "empty database query param → empty",
			req: &http.Request{
				URL: mustParseURL(t, "https://ch.example/?database="),
			},
			want: "",
		},
		{
			name: "case preserved",
			req: &http.Request{
				URL: mustParseURL(t, "https://ch.example/?database=Prod"),
			},
			want: "Prod",
		},
		{
			name: "nil request",
			req:  nil,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clickhouseHTTPSDatabase(tc.req); got != tc.want {
				t.Errorf("clickhouseHTTPSDatabase = %q, want %q", got, tc.want)
			}
		})
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
