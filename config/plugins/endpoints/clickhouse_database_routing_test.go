package endpoints

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/denoland/clawpatrol/config"
)

// compiledNative wraps a ClickhouseNativeEndpoint into a
// *config.CompiledEndpoint shaped just enough for the routing
// helper. Only Body, Name, and Plugin.Type are read.
func compiledNative(name string, body *ClickhouseNativeEndpoint) *config.CompiledEndpoint {
	return &config.CompiledEndpoint{
		Name:   name,
		Plugin: &config.Plugin{Type: "clickhouse_native"},
		Body:   body,
	}
}

func TestPickClickhouseNativeByDatabaseSpecificWins(t *testing.T) {
	prod := compiledNative("prod", &ClickhouseNativeEndpoint{Database: "analytics_prod"})
	dev := compiledNative("dev", &ClickhouseNativeEndpoint{Database: "analytics_dev"})
	catchAll := compiledNative("all", &ClickhouseNativeEndpoint{})
	cands := []*config.CompiledEndpoint{catchAll, prod, dev}

	if got := pickClickhouseNativeByDatabase(cands, "analytics_prod"); got != prod {
		t.Fatalf("want prod, got %v", got)
	}
	if got := pickClickhouseNativeByDatabase(cands, "analytics_dev"); got != dev {
		t.Fatalf("want dev, got %v", got)
	}
}

func TestPickClickhouseNativeByDatabaseFallsBackToCatchAll(t *testing.T) {
	prod := compiledNative("prod", &ClickhouseNativeEndpoint{Database: "analytics_prod"})
	catchAll := compiledNative("all", &ClickhouseNativeEndpoint{})
	cands := []*config.CompiledEndpoint{prod, catchAll}

	if got := pickClickhouseNativeByDatabase(cands, "analytics_dev"); got != catchAll {
		t.Fatalf("unmatched database should fall through to catch-all; got %v", got)
	}
	// Empty Hello.Database matches catch-all the same way.
	if got := pickClickhouseNativeByDatabase(cands, ""); got != catchAll {
		t.Fatalf("empty database should pick catch-all; got %v", got)
	}
}

func TestPickClickhouseNativeByDatabaseNoCatchAllNoMatchReturnsNil(t *testing.T) {
	prod := compiledNative("prod", &ClickhouseNativeEndpoint{Database: "analytics_prod"})
	dev := compiledNative("dev", &ClickhouseNativeEndpoint{Database: "analytics_dev"})
	cands := []*config.CompiledEndpoint{prod, dev}

	if got := pickClickhouseNativeByDatabase(cands, "other"); got != nil {
		t.Fatalf("no specific match and no catch-all should return nil; got %v", got)
	}
}

func TestPickClickhouseNativeByDatabaseEmptyInput(t *testing.T) {
	if got := pickClickhouseNativeByDatabase(nil, "x"); got != nil {
		t.Fatalf("empty candidates should return nil; got %v", got)
	}
}

func TestPickClickhouseNativeByDatabaseIgnoresWrongBody(t *testing.T) {
	// Defensive: a candidate whose Body isn't *ClickhouseNativeEndpoint
	// (e.g. accidental cross-plugin reuse) is skipped, not crashed on.
	bogus := &config.CompiledEndpoint{
		Name:   "bogus",
		Plugin: &config.Plugin{Type: "clickhouse_native"},
		Body:   struct{}{},
	}
	prod := compiledNative("prod", &ClickhouseNativeEndpoint{Database: "p"})
	if got := pickClickhouseNativeByDatabase([]*config.CompiledEndpoint{bogus, prod}, "p"); got != prod {
		t.Fatalf("non-native body should be skipped; got %v", got)
	}
}

func TestClickhouseHTTPSDatabaseFromRequest(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return u
	}
	cases := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "query parameter",
			req:  &http.Request{URL: mustURL("https://ch/?database=foo")},
			want: "foo",
		},
		{
			name: "header",
			req: &http.Request{
				URL:    mustURL("https://ch/"),
				Header: http.Header{"X-Clickhouse-Database": []string{"bar"}},
			},
			want: "bar",
		},
		{
			name: "query wins over header",
			req: &http.Request{
				URL:    mustURL("https://ch/?database=fromquery"),
				Header: http.Header{"X-Clickhouse-Database": []string{"fromheader"}},
			},
			want: "fromquery",
		},
		{
			name: "neither set",
			req:  &http.Request{URL: mustURL("https://ch/?other=1")},
			want: "",
		},
		{
			name: "case preserved",
			req:  &http.Request{URL: mustURL("https://ch/?database=Prod")},
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
			if got := ClickhouseHTTPSDatabaseFromRequest(tc.req); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPickClickhouseHTTPSEndpointByDatabase(t *testing.T) {
	prod := &ClickhouseHTTPSEndpoint{Database: "analytics_prod"}
	dev := &ClickhouseHTTPSEndpoint{Database: "analytics_dev"}
	catchAll := &ClickhouseHTTPSEndpoint{}
	cands := []*ClickhouseHTTPSEndpoint{catchAll, prod, dev}

	if got := PickClickhouseHTTPSEndpointByDatabase(cands, "analytics_prod"); got != prod {
		t.Fatalf("want prod, got %v", got)
	}
	if got := PickClickhouseHTTPSEndpointByDatabase(cands, "analytics_dev"); got != dev {
		t.Fatalf("want dev, got %v", got)
	}
	if got := PickClickhouseHTTPSEndpointByDatabase(cands, "other"); got != catchAll {
		t.Fatalf("unmatched should fall through to catch-all, got %v", got)
	}
	if got := PickClickhouseHTTPSEndpointByDatabase(cands, ""); got != catchAll {
		t.Fatalf("empty database should pick catch-all, got %v", got)
	}
	if got := PickClickhouseHTTPSEndpointByDatabase(nil, "x"); got != nil {
		t.Fatalf("nil candidates should return nil, got %v", got)
	}
	// No catch-all, no match: nil.
	noCatch := []*ClickhouseHTTPSEndpoint{prod, dev}
	if got := PickClickhouseHTTPSEndpointByDatabase(noCatch, "other"); got != nil {
		t.Fatalf("no catch-all, no match should return nil, got %v", got)
	}
}
