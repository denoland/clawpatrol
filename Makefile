.PHONY: build release dashboard test fmt fmt-check lint go-lint dashboard-lint clean install

build: dashboard
	go build -o clawpatrol ./cmd/clawpatrol

# release mirrors .github/workflows/release.yml: strip the symbol
# table and DWARF (-s -w) and rewrite source paths (-trimpath). On
# this tree that drops the binary from ~88 MB to ~62 MB without
# changing runtime behaviour. Use this when packaging for users —
# `make build` stays unstripped so panics keep file:line info.
release: dashboard
	go build -ldflags "-s -w" -trimpath -o clawpatrol ./cmd/clawpatrol

dashboard:
	cd dashboard && deno install && deno task build

test:
	go test ./...

# Our tracked Go sources, excluding the vendored upstream copy under
# third_party/ (a verbatim tailscale.com tree that must not be
# reformatted — see third_party/tailscale/PATCH.md).
GO_SRC = $(shell git ls-files '*.go' | grep -v '^third_party/')

fmt:
	gofmt -w $(GO_SRC)
	cd dashboard && deno task format

fmt-check:
	test -z "$$(gofmt -l $(GO_SRC))"
	cd dashboard && deno task format:check

lint: go-lint dashboard-lint

# `go-lint` requires the dashboard bundle so the //go:embed in
# dashboard/embed.go resolves at compile time. Depending on
# `dashboard` here makes a clean checkout work without manual ordering.
go-lint: dashboard
	golangci-lint run --timeout 5m ./...

dashboard-lint:
	cd dashboard && deno task lint

clean:
	rm -f clawpatrol
	rm -rf dashboard/dist dashboard/node_modules

install: build
	install -m 0755 clawpatrol $${PREFIX:-$$HOME/.local/bin}/clawpatrol
