package main

import (
	"encoding/json"
	"testing"
)

func TestLooksLikeSavedPlan(t *testing.T) {
	sp := savedPlan{
		Version:        savedPlanVersion,
		Config:         []byte("gateway {}\n"),
		Revision:       "abc",
		ExpectedSerial: 3,
		Added:          []string{"endpoint x"},
	}
	blob, err := json.Marshal(sp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, ok := looksLikeSavedPlan(blob)
	if !ok {
		t.Fatal("marshaled plan should be detected as a saved plan")
	}
	if got.ExpectedSerial != 3 || string(got.Config) != "gateway {}\n" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Raw HCL is not a saved plan.
	if _, ok := looksLikeSavedPlan([]byte("gateway {\n  state_dir = \"/x\"\n}\n")); ok {
		t.Fatal("HCL must not be mistaken for a saved plan")
	}
	// JSON without a version is not a saved plan.
	if _, ok := looksLikeSavedPlan([]byte(`{"foo":1}`)); ok {
		t.Fatal("versionless JSON must not be a saved plan")
	}
	// Empty input.
	if _, ok := looksLikeSavedPlan(nil); ok {
		t.Fatal("empty input must not be a saved plan")
	}
}
