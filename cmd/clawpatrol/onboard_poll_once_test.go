package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The approved auth material is a one-shot: the first poll after
// approval gets it, every later poll with the same device code is
// refused.
func TestOnboardPollDeliversAuthMaterialOnce(t *testing.T) {
	w := &webMux{onboard: newOnboardRegistry()}
	s := w.onboard.start()
	w.onboard.mu.Lock()
	s.approved = true
	s.authKey = "wg-key"
	s.apiToken = "api-token"
	s.loginServer = "wireguard://wg0"
	w.onboard.mu.Unlock()

	poll := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/onboard/poll?device_code="+s.deviceCode, nil)
		w.apiOnboardPoll(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v: %s", err, rec.Body.String())
		}
		return out
	}

	first := poll()
	if first["auth_key"] != "wg-key" || first["api_token"] != "api-token" {
		t.Fatalf("first poll = %v", first)
	}
	second := poll()
	if second["error"] != "expired_token" {
		t.Fatalf("second poll = %v, want expired_token", second)
	}
	if _, leaked := second["auth_key"]; leaked {
		t.Fatalf("second poll leaked auth material: %v", second)
	}
}
