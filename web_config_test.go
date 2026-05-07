package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIConfigPreviewFormatsAndDiffsWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	original := []byte("insecure_no_dashboard_secret = true\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	req := httptest.NewRequest(http.MethodPost, "/api/config/preview", strings.NewReader("insecure_no_dashboard_secret=false\n"))
	rr := httptest.NewRecorder()

	w.apiConfigPreview(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		OK        bool   `json:"ok"`
		Formatted string `json:"formatted"`
		Diff      string `json:"diff"`
		Bytes     int    `json:"bytes"`
		Revision  string `json:"revision"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !got.OK {
		t.Fatalf("ok = false")
	}
	if got.Formatted != "insecure_no_dashboard_secret = false\n" {
		t.Fatalf("formatted = %q", got.Formatted)
	}
	if got.Bytes != len(got.Formatted) {
		t.Fatalf("bytes = %d, want %d", got.Bytes, len(got.Formatted))
	}
	if got.Revision == "" {
		t.Fatalf("revision is empty")
	}
	for _, want := range []string{"--- gateway.hcl", "+++ formatted draft", "-insecure_no_dashboard_secret = true", "+insecure_no_dashboard_secret = false"} {
		if !strings.Contains(got.Diff, want) {
			t.Fatalf("diff missing %q:\n%s", want, got.Diff)
		}
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("preview wrote file: %q", contents)
	}
}

func TestAPIConfigSaveRequiresExpectedRevisionAndWritesFormattedHCL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte("insecure_no_dashboard_secret = true\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	rev, err := fileRevision(cfgPath)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}

	payload := `{"content":"insecure_no_dashboard_secret=false\n","expected_revision":"` + rev + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/save", strings.NewReader(payload))
	rr := httptest.NewRecorder()

	w.apiConfigSave(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if got, want := string(contents), "insecure_no_dashboard_secret = false\n"; got != want {
		t.Fatalf("saved content = %q, want %q", got, want)
	}
}

func TestAPIConfigSaveRejectsStaleRevision(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	original := []byte("insecure_no_dashboard_secret = true\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}

	payload := `{"content":"insecure_no_dashboard_secret=false\n","expected_revision":"stale"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/save", strings.NewReader(payload))
	rr := httptest.NewRecorder()

	w.apiConfigSave(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rr.Code, rr.Body.String())
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("stale save wrote file: %q", contents)
	}
}

func TestAPIConfigPutRequiresRevision(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	original := []byte("insecure_no_dashboard_secret = true\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}

	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader("insecure_no_dashboard_secret=false\n"))
	rr := httptest.NewRecorder()

	w.apiConfig(rr, req)

	if rr.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428, body = %s", rr.Code, rr.Body.String())
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("put without revision wrote file: %q", contents)
	}
}
