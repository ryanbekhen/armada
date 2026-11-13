MODULE   := github.com/ryanbekhen/armada
BIN      := bin/armada
DAEMON   := bin/armadad
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

export CGO_ENABLED := 0

.PHONY: all build build-bundle runtime-bundle test cover lint fmt vet vuln licenses licenses-save proto docs tidy check clean

all: check build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/armada
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(DAEMON) ./cmd/armadad

# Downloads the pinned containerd, runc, CNI plugins, and tini (ADR 0011),
# checks their SHA-256, and packs them for embedding.
runtime-bundle:
	go run ./internal/runtime/embedded/mkbundle -arch amd64
	go run ./internal/runtime/embedded/mkbundle -arch arm64

# Linux binaries as releases are built: armadad with the runtime bundle
# embedded, and the armada client.
build-bundle: runtime-bundle
	GOOS=linux GOARCH=$(or $(GOARCH),amd64) go build -trimpath -tags bundle -ldflags '$(LDFLAGS)' -o $(DAEMON)-linux-$(or $(GOARCH),amd64) ./cmd/armadad
	GOOS=linux GOARCH=$(or $(GOARCH),amd64) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)-linux-$(or $(GOARCH),amd64) ./cmd/armada

test:
	CGO_ENABLED=1 go test -race ./...

cover:
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

vet:
	go vet ./...

vuln:
	govulncheck ./...

docs: ## regenerate the command line reference in docs/cli
	go test ./internal/clidoc -run TestReferenceIsCurrent -update -count=1

proto:
	go build -o bin/tools/ google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc
	protoc -I api \
		--plugin=protoc-gen-go=bin/tools/protoc-gen-go \
		--plugin=protoc-gen-go-grpc=bin/tools/protoc-gen-go-grpc \
		--go_out=api --go_opt=paths=source_relative \
		--go-grpc_out=api --go-grpc_opt=paths=source_relative \
		api/armada/v1/*.proto

tidy:
	go mod tidy

# Everything CI runs, in one target.
check: vet lint test vuln

clean:
	rm -rf bin coverage.out internal/runtime/embedded/bundle

# Licenses of the Go modules the binaries are built from (THIRD_PARTY_NOTICES.md).
GO_LICENSES = go run github.com/google/go-licenses/v2@v2.0.1
ALLOWED_LICENSES = Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,CC0-1.0

licenses: ## fail when a Go module under a license outside ALLOWED_LICENSES is added
	$(GO_LICENSES) check ./cmd/... --allowed_licenses=$(ALLOWED_LICENSES)

licenses-save: ## copy every Go module's license and notice files into build/licenses (release archives)
	rm -rf build/licenses
	$(GO_LICENSES) save ./cmd/... --save_path=build/licenses 2>/dev/null
