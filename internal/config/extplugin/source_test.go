package extplugin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestParseSource(t *testing.T) {
	cases := []struct {
		in      string
		kind    sourceKind
		owner   string
		repo    string
		wantErr bool
	}{
		{in: "github.com/denoland/clawpatrol-customerio-plugin", kind: sourceGitHub, owner: "denoland", repo: "clawpatrol-customerio-plugin"},
		{in: "github.com/owner/repo.git", kind: sourceGitHub, owner: "owner", repo: "repo"},
		{in: "github.com/owner/repo/", kind: sourceGitHub, owner: "owner", repo: "repo"},
		{in: "/abs/path/plugin", kind: sourceLocal},
		{in: "./rel/plugin", kind: sourceLocal},
		{in: "~/p/plugin", kind: sourceLocal},
		{in: "bin/myplugin", kind: sourceLocal}, // bare relative stays local
		{in: "github.com/owner", wantErr: true},
		{in: "github.com/owner/repo/extra", wantErr: true},
		{in: "github.com//repo", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		got, err := parseSource(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSource(%q): want error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSource(%q): %v", c.in, err)
			continue
		}
		if got.Kind != c.kind || got.Owner != c.owner || got.Repo != c.repo {
			t.Errorf("parseSource(%q) = %+v, want kind=%d owner=%q repo=%q", c.in, got, c.kind, c.owner, c.repo)
		}
	}
}

func TestPluginSourceForRejectsVersionOnLocal(t *testing.T) {
	_, err := pluginSourceFor(config.PluginSource{Name: "x", Source: "./local", Version: "~> 1.0"})
	if err == nil || !strings.Contains(err.Error(), "only valid for a github.com") {
		t.Fatalf("want version-on-local error, got %v", err)
	}
	if _, err := pluginSourceFor(config.PluginSource{Name: "x", Source: "github.com/o/r", Version: "~> 1.0"}); err != nil {
		t.Fatalf("version on github source should be ok: %v", err)
	}
	if _, err := pluginSourceFor(config.PluginSource{Name: "x", Source: "./local"}); err != nil {
		t.Fatalf("local without version should be ok: %v", err)
	}
}

func TestProvenanceModeValidation(t *testing.T) {
	for _, s := range []string{"", "warn", "require", "off"} {
		if _, err := parseProvenanceMode(s); err != nil {
			t.Errorf("parseProvenanceMode(%q) errored: %v", s, err)
		}
	}
	if _, err := parseProvenanceMode("bogus"); err == nil {
		t.Error("parseProvenanceMode(bogus) should error")
	}
	// provenance only valid on a remote source.
	if _, err := pluginSourceFor(config.PluginSource{Name: "x", Source: "./local", Provenance: "require"}); err == nil ||
		!strings.Contains(err.Error(), "only valid for a github") {
		t.Fatalf("provenance on local should error, got %v", err)
	}
	if _, err := pluginSourceFor(config.PluginSource{Name: "x", Source: "github.com/o/r", Provenance: "bogus"}); err == nil {
		t.Error("invalid provenance value should be rejected")
	}
}

func rel(tag string, opts ...func(*ghRelease)) ghRelease {
	r := ghRelease{TagName: tag}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func TestResolveRelease(t *testing.T) {
	all := []ghRelease{
		rel("v1.0.0"),
		rel("v1.2.0"),
		rel("v1.2.4"),
		rel("v1.3.0"),
		rel("v2.0.0"),
		rel("v2.1.0-rc.1"),
		rel("not-a-version"),
		rel("v0.9.0-draft", func(r *ghRelease) { r.Draft = true }),
	}
	cases := []struct {
		constraint string
		want       string
		wantErr    bool
	}{
		{constraint: "", want: "v2.0.0"},         // newest stable, excludes rc
		{constraint: "~> 1.2", want: "v1.3.0"},   // >=1.2,<2.0
		{constraint: "~> 1.2.0", want: "v1.2.4"}, // >=1.2.0,<1.3.0
		{constraint: ">= 1.0, < 2.0", want: "v1.3.0"},
		{constraint: "1.2.0", want: "v1.2.0"},             // exact
		{constraint: "~> 3.0", wantErr: true},             // nothing matches
		{constraint: "= 2.1.0-rc.1", want: "v2.1.0-rc.1"}, // explicit prerelease pin
		{constraint: "bogus !! constraint", wantErr: true},
	}
	for _, c := range cases {
		_, v, err := resolveRelease(all, c.constraint)
		if c.wantErr {
			if err == nil {
				t.Errorf("resolveRelease(%q): want error, got %s", c.constraint, v)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveRelease(%q): %v", c.constraint, err)
			continue
		}
		if got := "v" + v.String(); got != c.want {
			t.Errorf("resolveRelease(%q) = %s, want %s", c.constraint, got, c.want)
		}
	}
}

func TestListReleasesPagination(t *testing.T) {
	// Two pages: 100 then 1 (so the client stops after page 2).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/releases" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			var b strings.Builder
			b.WriteString("[")
			for i := 0; i < 100; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"tag_name":"v1.0.%d"}`, i)
			}
			b.WriteString("]")
			_, _ = w.Write([]byte(b.String()))
		case "2":
			_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0","assets":[{"name":"a","browser_download_url":"http://x/a","size":3}]}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	c := &ghClient{http: srv.Client(), base: srv.URL}
	releases, err := c.listReleases(context.Background(), "o", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 101 {
		t.Fatalf("got %d releases, want 101", len(releases))
	}
	_, v, err := resolveRelease(releases, "")
	if err != nil || v.String() != "2.0.0" {
		t.Fatalf("resolve newest = %v (err %v), want 2.0.0", v, err)
	}
	if a, ok := releases[100].asset("a"); !ok || a.Size != 3 {
		t.Fatalf("asset lookup failed: %+v ok=%v", a, ok)
	}
}

func TestListReleasesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c := &ghClient{http: srv.Client(), base: srv.URL}
	if _, err := c.listReleases(context.Background(), "o", "r"); err == nil ||
		!strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("want HTTP 404 error, got %v", err)
	}
}
