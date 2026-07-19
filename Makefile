SHELL := /bin/sh

BINARY := bin/byos
PACKAGE := ./cmd/byos
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: all build run test vet fmt check clean docker-build docker-up docker-down help

all: build

build:
	@mkdir -p $(dir $(BINARY))
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BINARY) $(PACKAGE)

run:
	go run $(PACKAGE) serve

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

check: test vet
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.git/*'))" || { \
		echo 'Go files need formatting; run make fmt'; \
		gofmt -l $$(find . -name '*.go' -not -path './.git/*'); \
		exit 1; \
	}

docker-build:
	docker compose build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -rf bin

help:
	@printf '%s\n' \
		'build         Build bin/byos with version metadata' \
		'run           Run the server from source' \
		'test          Run all tests' \
		'vet           Run go vet' \
		'fmt           Format all Go files' \
		'check         Run tests, vet, and formatting checks' \
		'docker-build  Build the Compose image' \
		'docker-up     Build and start the Compose service' \
		'docker-down   Stop the Compose service' \
		'clean         Remove build artifacts'
