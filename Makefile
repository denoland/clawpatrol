.PHONY: build dashboard test fmt fmt-check lint clean install

build: dashboard
	go build -o clawpatrol ./cmd/clawpatrol

dashboard:
	cd dashboard && npm ci && npm run build

test:
	go test ./...

fmt:
	gofmt -w .
	cd dashboard && npm run format

fmt-check:
	test -z "$$(gofmt -l .)"
	cd dashboard && npm run format:check

lint:
	cd dashboard && npm run lint

clean:
	rm -f clawpatrol
	rm -rf dashboard/dist dashboard/node_modules

install: build
	install -m 0755 clawpatrol $${PREFIX:-$$HOME/.local/bin}/clawpatrol
