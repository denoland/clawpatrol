package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestReorderJoinArgsForFlagParseAcceptsFlagsAfterURL(t *testing.T) {
	got := reorderJoinArgsForFlagParse([]string{
		"https://deno.clawpatrol.dev",
		"--hostname", "magurobot",
		"--profile", "magurobot",
		"--whole-machine",
	})
	want := []string{
		"--hostname", "magurobot",
		"--profile", "magurobot",
		"--whole-machine",
		"https://deno.clawpatrol.dev",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered args mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestReorderJoinArgsForFlagParsePreservesLeadingFlags(t *testing.T) {
	got := reorderJoinArgsForFlagParse([]string{
		"--hostname=magurobot",
		"--profile", "magurobot",
		"https://deno.clawpatrol.dev",
	})
	want := []string{
		"--hostname=magurobot",
		"--profile", "magurobot",
		"https://deno.clawpatrol.dev",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered args mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRefuseSudoMessage(t *testing.T) {
	cases := []struct {
		name      string
		euid      int
		sudoUser  string
		wantBail  bool
		wantMatch string // substring the message should contain when wantBail
	}{
		{
			name:     "normal user, no sudo",
			euid:     1000,
			sudoUser: "",
			wantBail: false,
		},
		{
			name:     "real root (no SUDO_USER) — allowed",
			euid:     0,
			sudoUser: "",
			wantBail: false,
		},
		{
			name:     "root with SUDO_USER=root — allowed (sudo from root shell)",
			euid:     0,
			sudoUser: "root",
			wantBail: false,
		},
		{
			name:      "user ran `sudo clawpatrol join` — refuse",
			euid:      0,
			sudoUser:  "divy",
			wantBail:  true,
			wantMatch: "Try again as divy",
		},
		{
			name:      "subcmd is echoed back",
			euid:      0,
			sudoUser:  "alice",
			wantBail:  true,
			wantMatch: "clawpatrol join", // first %[1]s
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, refuse := refuseSudoMessage("join", c.euid, c.sudoUser)
			if refuse != c.wantBail {
				t.Fatalf("refuse=%v want=%v (msg=%q)", refuse, c.wantBail, msg)
			}
			if c.wantBail && !strings.Contains(msg, c.wantMatch) {
				t.Errorf("message missing %q\nfull:\n%s", c.wantMatch, msg)
			}
			if !c.wantBail && msg != "" {
				t.Errorf("expected empty message when not bailing, got %q", msg)
			}
		})
	}
}
