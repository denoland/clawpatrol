package main

import (
	"reflect"
	"testing"
)

// Repro for orchid#38: the documented `clawpatrol join <url> --flags`
// form must work even though Go's stdlib flag.Parse stops at the first
// non-flag token. Before the fix, passing the URL ahead of --profile /
// --hostname left those flags in fs.Args() and the positional check
// rejected the invocation with the misleading "usage" line.
func TestParseJoinFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want joinFlags
	}{
		{
			name: "url before flags (orchid#38 form)",
			args: []string{
				"https://deno.clawpatrol.dev",
				"--profile", "bot1",
				"--hostname", "agent-loop-bot1-abc",
			},
			want: joinFlags{
				gatewayURL: "https://deno.clawpatrol.dev",
				profile:    "bot1",
				hostname:   "agent-loop-bot1-abc",
			},
		},
		{
			name: "url after flags",
			args: []string{
				"--profile", "bot1",
				"--hostname", "agent-loop-bot1-abc",
				"https://deno.clawpatrol.dev",
			},
			want: joinFlags{
				gatewayURL: "https://deno.clawpatrol.dev",
				profile:    "bot1",
				hostname:   "agent-loop-bot1-abc",
			},
		},
		{
			name: "= form",
			args: []string{
				"https://deno.clawpatrol.dev",
				"--profile=bot1",
				"--hostname=agent-loop-bot1-abc",
			},
			want: joinFlags{
				gatewayURL: "https://deno.clawpatrol.dev",
				profile:    "bot1",
				hostname:   "agent-loop-bot1-abc",
			},
		},
		{
			name: "bool flag interleaved with positional",
			args: []string{
				"--whole-machine",
				"https://deno.clawpatrol.dev",
				"--profile", "bot1",
			},
			want: joinFlags{
				gatewayURL:   "https://deno.clawpatrol.dev",
				profile:      "bot1",
				wholeMachine: true,
			},
		},
		{
			name: "single-dash flag (Go flag.Parse syntax)",
			args: []string{"https://gw", "-profile", "bot1"},
			want: joinFlags{
				gatewayURL: "https://gw",
				profile:    "bot1",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseJoinFlags(tc.args)
			if err != nil {
				t.Fatalf("parseJoinFlags(%v) error: %v", tc.args, err)
			}
			// Only compare the fields the test sets; gwName + caOut
			// carry compiled-in defaults that aren't germane.
			gotSubset := joinFlags{
				gatewayURL:   got.gatewayURL,
				profile:      got.profile,
				hostname:     got.hostname,
				wholeMachine: got.wholeMachine,
				skipTrust:    got.skipTrust,
			}
			wantSubset := joinFlags{
				gatewayURL:   tc.want.gatewayURL,
				profile:      tc.want.profile,
				hostname:     tc.want.hostname,
				wholeMachine: tc.want.wholeMachine,
				skipTrust:    tc.want.skipTrust,
			}
			if !reflect.DeepEqual(gotSubset, wantSubset) {
				t.Fatalf("parseJoinFlags(%v) = %+v, want %+v", tc.args, gotSubset, wantSubset)
			}
		})
	}
}

func TestParseJoinFlagsErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no positional", []string{"--profile", "bot1"}},
		{"empty url", []string{""}},
		{"two positionals", []string{"https://gw", "extra"}},
		{"no args", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseJoinFlags(tc.args); err == nil {
				t.Fatalf("parseJoinFlags(%v) = nil error, want error", tc.args)
			}
		})
	}
}
