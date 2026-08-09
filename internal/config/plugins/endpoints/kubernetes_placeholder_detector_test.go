package endpoints

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/match"
)

func TestKubernetesDetectPlaceholderMatchesExactBearerValue(t *testing.T) {
	detector := KubernetesEndpointRuntime{}
	candidates := []string{"PH_k8s", "PH_k8s_admin"}

	tests := []struct {
		name          string
		authorization string
		want          string
	}{
		{name: "first placeholder", authorization: "Bearer PH_k8s", want: "PH_k8s"},
		{name: "overlapping placeholder", authorization: "Bearer PH_k8s_admin", want: "PH_k8s_admin"},
		{name: "case insensitive scheme", authorization: "bearer PH_k8s", want: "PH_k8s"},
		{name: "unknown placeholder", authorization: "Bearer PH_unknown"},
		{name: "missing placeholder"},
		{name: "partial placeholder", authorization: "Bearer PH_k8s_admin_suffix"},
		{name: "wrong scheme", authorization: "Token PH_k8s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.authorization != "" {
				headers.Set("Authorization", tt.authorization)
			}
			got := detector.DetectPlaceholder(&match.Request{Headers: headers}, candidates)
			if got != tt.want {
				t.Fatalf("DetectPlaceholder() = %q, want %q", got, tt.want)
			}
		})
	}
}
