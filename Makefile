.PHONY: build dashboard test fmt fmt-check lint clean install

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

lint:
	cd dashboard && deno task lint

clean:
	rm -f clawpatrol
	rm -rf dashboard/dist dashboard/node_modules

install: build
	install -m 0755 clawpatrol $${PREFIX:-$$HOME/.local/bin}/clawpatrol
