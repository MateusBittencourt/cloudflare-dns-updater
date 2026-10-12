.PHONY: build test

build:
	go build -trimpath -ldflags="-s -w" -o cloudflare-dns-updater .

test:
	go test ./...
