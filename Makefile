.PHONY: build test lint clean install

BINARY_NAME=kubectl-readonly
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

test:
	go test -v ./...

test-cover:
	go test -cover ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-*

install:
	go install $(LDFLAGS) .
