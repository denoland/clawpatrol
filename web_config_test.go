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
		OK           bool   `json:"ok"`
		Formatted    string `json:"formatted"`
		Diff         string `json:"diff"`
		Bytes        int    `json:"bytes"`
		Revision     string `json:"revision"`
		PreviewToken string `json:"preview_token"`
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
	if got.PreviewToken == "" {
		t.Fatalf("preview token is empty")
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

func TestUnifiedDiffSplitsDistantChangesIntoSeparateHunks(t *testing.T) {
	oldText := strings.Join([]string{
		"line 01",
		"line 02",
		"line 03",
		"line 04",
		"line 05",
		"line 06",
		"line 07",
		"line 08",
		"line 09",
		"line 10",
		"line 11",
		"line 12",
		"line 13",
		"line 14",
		"line 15",
	}, "\n") + "\n"
	newText := strings.Join([]string{
		"line 01",
		"line 02 changed",
		"line 03",
		"line 04",
		"line 05",
		"line 06",
		"line 07",
		"line 08",
		"line 09",
		"line 10",
		"line 11",
		"line 12",
		"line 13 changed",
		"line 14",
		"line 15",
	}, "\n") + "\n"

	diff := unifiedDiff("gateway.hcl", "formatted draft", oldText, newText)

	for _, want := range []string{
		"--- gateway.hcl",
		"+++ formatted draft",
		"@@ -1,5 +1,5 @@",
		"@@ -10,6 +10,6 @@",
		"-line 02",
		"+line 02 changed",
		"-line 13",
		"+line 13 changed",
	} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff missing %q:\n%s", want, diff)
		}
	}
	if strings.Count(diff, "@@") != 4 {
		t.Fatalf("hunk header count = %d, want 2 headers:\n%s", strings.Count(diff, "@@")/2, diff)
	}
	if strings.Contains(diff, " line 07\n") {
		t.Fatalf("diff included distant unchanged middle context:\n%s", diff)
	}
}

func TestAPIConfigSaveRequiresPreviewTokenAndWritesFormattedHCL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	if err := os.WriteFile(cfgPath, []byte("insecure_no_dashboard_secret = true\n"), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}

	preview := previewConfigForTest(t, w, "insecure_no_dashboard_secret=false\n")
	payload := `{"content":"` + jsonEscape(preview.Formatted) + `","expected_revision":"` + preview.Revision + `","preview_token":"` + preview.PreviewToken + `"}`
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
	preview := previewConfigForTest(t, w, "insecure_no_dashboard_secret=false\n")
	if err := os.WriteFile(cfgPath, []byte("insecure_no_dashboard_secret = false\n"), 0o600); err != nil {
		t.Fatalf("concurrent write: %v", err)
	}

	payload := `{"content":"` + jsonEscape(preview.Formatted) + `","expected_revision":"` + preview.Revision + `","preview_token":"` + preview.PreviewToken + `"}`
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
	if got, want := string(contents), "insecure_no_dashboard_secret = false\n"; got != want {
		t.Fatalf("stale save changed file: %q", contents)
	}
}

func TestAPIConfigSaveRejectsUnpreviewedContent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.hcl")
	original := []byte("insecure_no_dashboard_secret = true\n")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	w := &webMux{g: &Gateway{cfgPath: cfgPath}}
	preview := previewConfigForTest(t, w, "insecure_no_dashboard_secret=false\n")

	payload := `{"content":"insecure_no_dashboard_secret = true\n","expected_revision":"` + preview.Revision + `","preview_token":"` + preview.PreviewToken + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/save", strings.NewReader(payload))
	rr := httptest.NewRecorder()

	w.apiConfigSave(rr, req)

	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412, body = %s", rr.Code, rr.Body.String())
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("unpreviewed save wrote file: %q", contents)
	}
}

func TestAPIConfigPutIsReadOnly(t *testing.T) {
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

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405, body = %s", rr.Code, rr.Body.String())
	}
	contents, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	if !bytes.Equal(contents, original) {
		t.Fatalf("put without revision wrote file: %q", contents)
	}
}

type configPreviewForTest struct {
	Formatted    string `json:"formatted"`
	Revision     string `json:"revision"`
	PreviewToken string `json:"preview_token"`
}

func previewConfigForTest(t *testing.T, w *webMux, body string) configPreviewForTest {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/config/preview", strings.NewReader(body))
	rr := httptest.NewRecorder()
	w.apiConfigPreview(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got configPreviewForTest
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("preview json: %v", err)
	}
	if got.Formatted == "" || got.Revision == "" || got.PreviewToken == "" {
		t.Fatalf("incomplete preview: %+v", got)
	}
	return got
}

func jsonEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b[1 : len(b)-1])
}
