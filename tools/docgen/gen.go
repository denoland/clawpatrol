// Package main hosts the docgen generator and its drift-check test.
//
// Regenerate the committed config reference page from anywhere in the
// repo:
//
//	go run ./tools/docgen -out site/doc/15-config-reference.md
//
// The drift check (`go test ./tools/docgen/...`) fails CI when the
// committed file no longer matches what the generator produces against
// the current plugin sources.
package main

//go:generate go run . -root ../.. -out ../../site/doc/15-config-reference.md
