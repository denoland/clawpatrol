package https_test

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/config/facet"

	_ "github.com/denoland/clawpatrol/config/plugins/facets/https"
)

func TestHTTPTemplateRendersFromMatcherBindings(t *testing.T) {
	r, err := facet.NewTemplate("http", `"agent wants " + http.method + " " + http.path`)
	if err != nil {
		t.Fatalf("NewTemplate: %v", err)
	}
	out, err := r.Render(httpReq("GET", "/v1/messages"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got, want := out, "agent wants get /v1/messages"; got != want {
		t.Fatalf("Render = %q, want %q", got, want)
	}
}

func TestHTTPTemplateRejectsNonStringOutput(t *testing.T) {
	_, err := facet.NewTemplate("http", "http.method == 'GET'")
	if err == nil {
		t.Fatal("NewTemplate: expected error for bool output, got nil")
	}
	if !strings.Contains(err.Error(), "string") {
		t.Fatalf("expected string-type error, got %v", err)
	}
}

func TestHTTPTemplateRejectsUnknownBindings(t *testing.T) {
	_, err := facet.NewTemplate("http", `"x" + http.no_such_field`)
	if err == nil {
		t.Fatal("NewTemplate: expected error for unknown sub-field, got nil")
	}
}

func TestHTTPTemplateRejectsBadCEL(t *testing.T) {
	_, err := facet.NewTemplate("http", "this is not cel")
	if err == nil {
		t.Fatal("NewTemplate: expected parse error, got nil")
	}
}

func TestHTTPTemplateMultiLineConcat(t *testing.T) {
	r, err := facet.NewTemplate("http", `"line 1\n" + http.method + "\nline 3"`)
	if err != nil {
		t.Fatalf("NewTemplate: %v", err)
	}
	out, err := r.Render(httpReq("POST", "/x"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "line 1\npost\nline 3"; out != want {
		t.Fatalf("Render = %q, want %q", out, want)
	}
}
