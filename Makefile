.PHONY: build test test-cover test-smoke test-integration test-all lint clean install krew-manifest

BINARY_NAME=kubectl-readonly
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X github.com/Evaneos/kubectl-readonly/internal/cli.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .
	go build $(LDFLAGS) -o $(BINARY_NAME)-strict ./cmd/$(BINARY_NAME)-strict
	go build $(LDFLAGS) -o $(BINARY_NAME)-leaky ./cmd/$(BINARY_NAME)-leaky

test:
	go test -v ./...

test-cover:
	go test -cover ./...

# Smoke tests - fast validation without cluster (requires kubectl and built binary)
test-smoke: build
	go test -tags=integration -v -run TestSmoke ./...

# Full integration tests with kind cluster (requires kind, kubectl, Docker)
test-integration: build
	go test -tags=integration -v ./... ; \
	exit_code=$$? ; \
	kind delete cluster --name kubectl-readonly-test 2>/dev/null || true ; \
	exit $$exit_code

# Run all tests: unit -> smoke -> integration
test-all: test test-smoke test-integration

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

install:
	go install $(LDFLAGS) . ./cmd/...

# Generate a Krew manifest for a release (usage: make krew-manifest VERSION=v0.3.0 [PLUGIN=readonly-strict])
krew-manifest:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make krew-manifest VERSION=v0.3.0"; exit 1; fi
	./scripts/generate-krew-manifest.sh $(VERSION) $(PLUGIN)

# Delete kind test cluster
clean-kind:
	kind delete cluster --name kubectl-readonly-test 2>/dev/null || true
