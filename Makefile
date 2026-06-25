GO ?= go
VERSION ?= dev

.PHONY: build test fmt vet release clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/cfnat ./cmd/cfnat

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

release: clean
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/cfnat-linux-amd64 ./cmd/cfnat
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/cfnat-linux-arm64 ./cmd/cfnat
	GOOS=linux GOARCH=386 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o dist/cfnat-linux-386 ./cmd/cfnat

clean:
	rm -rf dist

