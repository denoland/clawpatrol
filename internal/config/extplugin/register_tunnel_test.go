package extplugin

import (
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// TestTunnelReservedAttrRejected verifies a plugin tunnel manifest that
// declares a framework-reserved attr name (via / share / keepalive /
// credential) is rejected at registration, rather than silently having
// the operator's value stolen by the framework-attr peel (decodeTunnelCommon).
func TestTunnelReservedAttrRejected(t *testing.T) {
	for _, reserved := range []string{"via", "share", "keepalive", "credential"} {
		t.Run(reserved, func(t *testing.T) {
			// The client only needs to exist — the guard fires before any RPC.
			client, cleanup := newCredentialPluginTestClient(t, &credentialPluginTestServer{
				typeName: "unused", seen: make(chan *pb.InjectHTTPRequest, 1),
			})
			defer cleanup()

			typeName := fmt.Sprintf("extplugin_test_tun_%d", time.Now().UnixNano())
			diags := RegisterManifest(client, &pb.ManifestResponse{
				Name: "exttuntest",
				Tunnels: []*pb.TunnelDecl{{
					TypeName: typeName,
					Schema:   &pb.Schema{Fields: []*pb.SchemaField{{Name: reserved, TypeString: "string"}}},
				}},
			})
			if !diags.HasErrors() {
				t.Fatalf("expected error for tunnel declaring reserved attr %q", reserved)
			}
			if got := diags.Error(); !strings.Contains(got, "reserved attribute") || !strings.Contains(got, reserved) {
				t.Fatalf("unexpected diagnostics: %v", got)
			}
		})
	}
}
