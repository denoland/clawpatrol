package main

import (
	"reflect"
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
