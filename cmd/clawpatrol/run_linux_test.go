//go:build linux

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// TestLastLineWriter pins the contract used to surface the relay
// supervisor's cause-of-death: the writer must (a) forward every byte
// to the underlying sink (so live logs aren't suppressed), and (b)
// expose the trailing non-empty line so the parent can quote it on
// unexpected exit.
func TestLastLineWriter(t *testing.T) {
	cases := []struct {
		name   string
		writes []string
		want   string
	}{
		{
			name:   "single line no trailing newline",
			writes: []string{"hello world"},
			want:   "hello world",
		},
		{
			name:   "two lines trailing newline",
			writes: []string{"first\nsecond\n"},
			want:   "second",
		},
		{
			name:   "split writes",
			writes: []string{"par", "tial\nsec", "ond line\n"},
			want:   "second line",
		},
		{
			name:   "trailing whitespace stripped",
			writes: []string{"last line   \n\n\r\n"},
			want:   "last line",
		},
		{
			name:   "empty",
			writes: nil,
			want:   "",
		},
		{
			name:   "only newlines",
			writes: []string{"\n\n\n"},
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sink bytes.Buffer
			lw := newLastLineWriter(&sink)
			joined := strings.Join(tc.writes, "")
			for _, w := range tc.writes {
				n, err := lw.Write([]byte(w))
				if err != nil {
					t.Fatalf("Write: %v", err)
				}
				if n != len(w) {
					t.Fatalf("Write n=%d, want %d", n, len(w))
				}
			}
			if got := sink.String(); got != joined {
				t.Errorf("sink got %q, want %q (writer must pass through every byte)", got, joined)
			}
			if got := lw.LastLine(); got != tc.want {
				t.Errorf("LastLine() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLastLineWriterBounded ensures a long-running noisy child can't
// drive the ring buffer unbounded.
func TestLastLineWriterBounded(t *testing.T) {
	lw := newLastLineWriter(nil)
	// Write well over lastLineMaxBytes.
	chunk := strings.Repeat("a", 1024)
	for i := 0; i < 20; i++ {
		if _, err := lw.Write([]byte(chunk + "\n")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := len(lw.buf); got > lastLineMaxBytes {
		t.Fatalf("buf size %d exceeds bound %d", got, lastLineMaxBytes)
	}
	if got := lw.LastLine(); got == "" {
		t.Fatal("LastLine empty after writes")
	}
}

func TestSplitWGAddresses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			// Regression: gateway-emitted wg-quick conf carries both
			// v4 and v6 in a single `Address =` line. Passing the
			// whole comma-joined string to `ip addr add` fails with
			// "any valid prefix is expected rather than ...".
			name: "dual stack",
			in:   "10.55.0.5/32, fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "dual stack no space after comma",
			in:   "10.55.0.5/32,fd77::5/128",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "v4 only",
			in:   "10.55.0.5/32",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "v6 only",
			in:   "fd77::5/128",
			want: []string{"fd77::5/128"},
		},
		{
			name: "missing prefix v4 defaults to /32",
			in:   "10.55.0.5",
			want: []string{"10.55.0.5/32"},
		},
		{
			name: "missing prefix v6 defaults to /128",
			in:   "fd77::5",
			want: []string{"fd77::5/128"},
		},
		{
			name: "extra whitespace and empty parts",
			in:   "  10.55.0.5/32 ,, fd77::5/128 ,",
			want: []string{"10.55.0.5/32", "fd77::5/128"},
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
		{
			name: "only whitespace and commas",
			in:   " , , ",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitWGAddresses(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitWGAddresses(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}
