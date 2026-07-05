# Makefile for altinity-mcp

VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build test vet fmt tidy clean docker run help

all: build

## build: build the altinity-mcp and jwe-token-generator binaries into the project root
build: altinity-mcp jwe-token-generator

## altinity-mcp: build the altinity-mcp binary into the project root
altinity-mcp: $(shell find cmd/altinity-mcp pkg -type f -name '*.go' 2>/dev/null) go.mod go.sum
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o altinity-mcp ./cmd/altinity-mcp

## jwe-token-generator: build the jwe-token-generator binary into the project root
jwe-token-generator: $(shell find cmd/jwe_auth pkg/jwe_auth -type f -name '*.go' 2>/dev/null) go.mod go.sum
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o jwe-token-generator ./cmd/jwe_auth

## test: run all unit tests
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go sources
fmt:
	go fmt ./...

## tidy: tidy go.mod / go.sum
tidy:
	go mod tidy

## run: build and run altinity-mcp (pass args via ARGS=)
run: altinity-mcp
	./altinity-mcp $(ARGS)

## docker: build the container image (tag with VERSION, also tag :latest)
docker: build
	docker build -t ghcr.io/altinity/altinity-mcp:$(VERSION) -t ghcr.io/altinity/altinity-mcp:latest .

## clean: remove built binaries
clean:
	rm -f ./altinity-mcp ./jwe-token-generator
	go clean -testcache

## help: show this help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^## [a-zA-Z_-]+:/ {sub(/^## /,""); split($$0,a,":"); printf "  \033[36m%-22s\033[0m %s\n", a[1], a[2]}' $(MAKEFILE_LIST)
