package endpoints

import (
	"strings"
	"testing"
)

// The statement text usually starts with its verb; pgSummary must not
// prepend it again ("NOTIFY NOTIFY reload"). When it doesn't — CTE
// shadow sub-statements, WITH ... INSERT — the verb is the only action
// keyword on the card and stays.
func TestPGSummary(t *testing.T) {
	cases := []struct {
		name string
		info pgInfo
		want string
	}{
		{
			name: "statement is not prefixed with the verb",
			info: pgInfo{Verb: "notify", Statement: "NOTIFY reload, 'now'"},
			want: "NOTIFY reload, 'now'",
		},
		{
			name: "verb match ignores case and leading whitespace",
			info: pgInfo{Verb: "select", Tables: []string{"users"}, Statement: "  select id from users"},
			want: "tables=[users] select id from users",
		},
		{
			name: "verb only when there is no statement",
			info: pgInfo{Verb: "select", Tables: []string{"users"}},
			want: "SELECT tables=[users]",
		},
		{
			name: "cte shadow sub-statement keeps the verb",
			info: pgInfo{Verb: "delete", Tables: []string{"users"}, Statement: "x"},
			want: "DELETE tables=[users] x",
		},
		{
			name: "with-cte keeps the inner verb",
			info: pgInfo{Verb: "insert", Statement: "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x"},
			want: "INSERT WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
		},
		{
			name: "verb prefix of a longer word does not count",
			info: pgInfo{Verb: "select", Statement: "selective"},
			want: "SELECT selective",
		},
		{
			name: "unparseable statement has no verb and no leading blank",
			info: pgInfo{Statement: "SELEC oops"},
			want: "SELEC oops",
		},
		{
			name: "long statement is truncated",
			info: pgInfo{Verb: "select", Statement: "SELECT " + strings.Repeat("x", 100)},
			want: "SELECT " + strings.Repeat("x", 73) + "...",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pgSummary(tc.info); got != tc.want {
				t.Fatalf("pgSummary(%#v) = %q, want %q", tc.info, got, tc.want)
			}
		})
	}
}
