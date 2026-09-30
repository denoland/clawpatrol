package main

import (
	"reflect"
	"testing"
)

func TestReorderJoinArgsForFlagParseAcceptsFlagsAfterURL(t *testing.T) {
	got := reorderJoinArgsForFlagParse([]string{
		"https://gateway.example.com",
		"--hostname", "magurobot",
		"--profile", "magurobot",
		"--whole-machine",
	})
	want := []string{
		"--hostname", "magurobot",
		"--profile", "magurobot",
		"--whole-machine",
		"https://gateway.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered args mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestReorderJoinArgsForFlagParsePreservesLeadingFlags(t *testing.T) {
	got := reorderJoinArgsForFlagParse([]string{
		"--hostname=magurobot",
		"--profile", "magurobot",
		"https://gateway.example.com",
	})
	want := []string{
		"--hostname=magurobot",
		"--profile", "magurobot",
		"https://gateway.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered args mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

// TestReorderJoinArgsForFlagParseConsumesValueFlagsAfterURL covers every flag
// that takes a separate value in the URL-first form the CLI help shows. A flag
// missing from the reorder switch leaves its value behind as a positional and
// swallows the gateway URL as the flag's value instead, so the command fails on
// a URL the operator did type correctly.
func TestReorderJoinArgsForFlagParseConsumesValueFlagsAfterURL(t *testing.T) {
	const url = "https://gateway.example.com"
	for _, flag := range []string{
		"--hostname", "--profile", "--name", "--ca-dir", "--ca-fingerprint",
	} {
		got := reorderJoinArgsForFlagParse([]string{url, flag, "value"})
		want := []string{flag, "value", url}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s must consume its value\n got: %#v\nwant: %#v", flag, got, want)
		}
	}
}
