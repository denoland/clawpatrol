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
