.PHONY: build dashboard test fmt fmt-check lint go-lint dashboard-lint clean install

build: dashboard
	go build -o clawpatrol ./cmd/clawpatrol

dashboard:
	cd dashboard && deno install && deno task build

test:
	go test ./...

fmt:
	gofmt -w .
	cd dashboard && deno task format

fmt-check:
	test -z "$$(gofmt -l .)"
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
