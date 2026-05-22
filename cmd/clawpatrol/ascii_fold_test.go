package main

import "testing"

func TestEqualFoldASCII(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"a", "A", true},
		{"Set-Cookie", "set-cookie", true},
		{"Set-Cookie", "SET-COOKIE", true},
		{"WWW-Authenticate", "Www-Authenticate", true},
		{"x", "y", false},
		{"set-cookie", "set-cooki", false},
		{"set-cookie!", "set-cookie", false},
	}
	for _, tc := range cases {
		if got := equalFoldASCII(tc.a, tc.b); got != tc.want {
			t.Errorf("equalFoldASCII(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestContainsFoldASCII(t *testing.T) {
	cases := []struct {
		s, sub string
		want   bool
	}{
		{"", "", true},
		{"abc", "", true},
		{"abc", "a", true},
		{"X-AUTH-TOKEN", "auth", true},
		{"Set-Cookie", "cook", true},
		{"Set-Cookie", "Cook", true},
		{"x-trace-id", "auth", false},
		{"a", "ab", false},
		{"AB", "abc", false},
	}
	for _, tc := range cases {
		if got := containsFoldASCII(tc.s, tc.sub); got != tc.want {
			t.Errorf("containsFoldASCII(%q,%q)=%v want %v", tc.s, tc.sub, got, tc.want)
		}
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Authorization", true},
		{"X-Api-Key", true},
		{"X-Api-Token", true},
		{"set-cookie", true},
		{"COOKIE", true},
		{"X-Secret-Foo", true},
		{"X-Trace-Id", false},
		{"Content-Type", false},
		{"X-Forwarded-For", false},
	}
	for _, tc := range cases {
		if got := isSensitiveHeader(tc.name); got != tc.want {
			t.Errorf("isSensitiveHeader(%q)=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestUpperLowerASCII(t *testing.T) {
	if got := upperASCII("Post"); got != "POST" {
		t.Errorf("upperASCII Post=%q want POST", got)
	}
	if got := lowerASCII("HTTPS"); got != "https" {
		t.Errorf("lowerASCII HTTPS=%q want https", got)
	}
	// Already-canonical inputs return the original string by identity
	// to avoid the allocation; just sanity-check the value.
	if got := upperASCII("POST"); got != "POST" {
		t.Errorf("upperASCII POST=%q want POST", got)
	}
	if got := lowerASCII("https"); got != "https" {
		t.Errorf("lowerASCII https=%q want https", got)
	}
	if got := lowerASCII(""); got != "" {
		t.Errorf("lowerASCII empty: %q", got)
	}
}
