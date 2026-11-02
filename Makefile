MODULE   := github.com/ryanbekhen/armada
BIN      := bin/armada
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all build build-bundle runtime-bundle test cover lint fmt vet vuln proto tidy check clean

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/armada

# Downloads the pinned containerd, runc, CNI plugins, and tini (ADR 0011),
# checks their SHA-256, and packs them for embedding.
runtime-bundle:
	go run ./internal/runtime/embedded/mkbundle -arch amd64
	go run ./internal/runtime/embedded/mkbundle -arch arm64

# A Linux binary with the runtime bundle embedded (as releases are built).
build-bundle: runtime-bundle
	GOOS=linux GOARCH=$(or $(GOARCH),amd64) go build -trimpath -tags bundle -ldflags '$(LDFLAGS)' -o $(BIN)-linux-$(or $(GOARCH),amd64) ./cmd/armada

test:
	CGO_ENABLED=1 go test -race ./...

cover:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# Lint for Linux too: the runtime code is mostly *_linux.go, which a
# macOS run would skip.
lint:
	golangci-lint run
	GOOS=linux golangci-lint run

fmt:
	golangci-lint fmt

vet:
	go vet ./...

vuln:
	govulncheck ./...

proto:
	go build -o bin/tools/ google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc
	protoc -I api \
		--plugin=protoc-gen-go=bin/tools/protoc-gen-go \
		--plugin=protoc-gen-go-grpc=bin/tools/protoc-gen-go-grpc \
		--go_out=api --go_opt=paths=source_relative \
		--go-grpc_out=api --go-grpc_opt=paths=source_relative \
		api/armada/v1/*.proto api/armada/driver/v1/*.proto

tidy:
	go mod tidy

# Everything CI runs, in one target.
check: vet lint test vuln

clean:
	rm -rf bin coverage.out internal/runtime/embedded/bundle
