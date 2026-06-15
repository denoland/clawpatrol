package config

import "testing"

func TestGenAITelemetryAccessorsAbsent(t *testing.T) {
	// No genai_telemetry block → disabled, content off.
	gw, diags := LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`), "genai-absent.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if gw.GenAITelemetryEnabled() {
		t.Error("GenAITelemetryEnabled() = true with no block, want false")
	}
	if gw.GenAITelemetryIncludeContent() {
		t.Error("GenAITelemetryIncludeContent() = true with no block, want false")
	}
}

func TestGenAITelemetryEnabledNoContent(t *testing.T) {
	// Empty block → base export on, content still off (the safe default).
	gw, diags := LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  genai_telemetry {}
}
`), "genai-base.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if !gw.GenAITelemetryEnabled() {
		t.Error("GenAITelemetryEnabled() = false with block present, want true")
	}
	if gw.GenAITelemetryIncludeContent() {
		t.Error("GenAITelemetryIncludeContent() = true without opt-in, want false")
	}
}

func TestGenAITelemetryContentOptIn(t *testing.T) {
	gw, diags := LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  genai_telemetry { include_message_content = true }
}
`), "genai-content.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if !gw.GenAITelemetryEnabled() {
		t.Error("GenAITelemetryEnabled() = false, want true")
	}
	if !gw.GenAITelemetryIncludeContent() {
		t.Error("GenAITelemetryIncludeContent() = false with opt-in, want true")
	}
}

func TestGenAITelemetryNilReceiverSafe(t *testing.T) {
	var g *Gateway
	if g.GenAITelemetryEnabled() || g.GenAITelemetryIncludeContent() {
		t.Error("nil receiver should report disabled")
	}
	g = &Gateway{}
	if g.GenAITelemetryEnabled() || g.GenAITelemetryIncludeContent() {
		t.Error("nil Settings should report disabled")
	}
}
