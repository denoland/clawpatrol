package main

import "testing"

func TestFunnelAllowlistIncludesOnlyPublicBootstrapWebhookAndHITLStatus(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/api/onboard/start", want: true},
		{path: "/api/onboard/poll", want: true},
		{path: "/api/onboard/claim", want: true},
		{path: "/api/cred/slack/interactive", want: true},
		{path: "/api/hitl/operations/hitl_op_test/status", want: true},
		{path: "/api/hitl/operations/hitl_op_test/status/extra", want: false},
		{path: "/api/hitl/pending", want: false},
		{path: "/api/hitl/decide", want: false},
		{path: "/api/config", want: false},
		{path: "/api/onboard/approve", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := funnelAllowsPublicPath(tc.path); got != tc.want {
				t.Fatalf("funnelAllowsPublicPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
