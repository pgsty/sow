SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO ?= go
GORELEASER ?= goreleaser
VERSION ?= 0.2.0
TEST_TIMEOUT ?= 60m
CORE_TEST_TIMEOUT ?= 20m
RACE_TIMEOUT ?= 30m
ARGS ?=

ROOT_DIR := $(CURDIR)
BIN_DIR := $(ROOT_DIR)/bin
DIST_DIR := $(ROOT_DIR)/dist
BINARY := $(BIN_DIR)/sow
CLEAN_DELIVERY_OUT ?= $(if $(TMPDIR),$(TMPDIR),/tmp)/sow-clean-delivery
LDFLAGS := -s -w -X github.com/pgsty/sow/internal/v2cli.Version=$(VERSION)
CORE_PACKAGES := ./internal/v2/... ./internal/v2cli ./internal/aptrepo ./internal/yumrepo

.PHONY: all help version build run install fmt fmt-check tidy tidy-check vet lint \
	test test-go test-rpm test-edge test-core test-v2 race check clean-delivery \
	goreleaser-check release-local release clean clean-bin clean-dist

all: build

help:
	@printf '%s\n' \
		'SOW v$(VERSION)' \
		'' \
		'  make build           Fast local go build to bin/sow' \
		'  make run ARGS=...    Run the CLI from source (example: ARGS=version)' \
		'  make install         Install sow with the release version embedded' \
		'  make test            Run all Go modules and edge contract tests' \
		'  make test-core       Run the focused repository-manager tests' \
		'  make race            Race-test the core repository packages' \
		'  make check           Run format, module, vet, lint, and focused tests' \
		'  make clean-delivery  Rebuild and verify the deterministic source archive' \
		'  make release-local   Build local archives and Linux packages with GoReleaser' \
		'  make release         Run all local gates, then build the GoReleaser snapshot' \
		'  make clean           Remove only managed bin/ and dist/ outputs'

version:
	@printf '%s\n' '$(VERSION)'

build:
	@mkdir -p '$(BIN_DIR)'
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o '$(BINARY)' ./cmd/sow

run:
	$(GO) run -trimpath -ldflags '$(LDFLAGS)' ./cmd/sow $(ARGS)

install:
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/sow

fmt:
	@files="$$(find cmd internal test -type f -name '*.go' -print)"; \
		test -z "$$files" || gofmt -w $$files

fmt-check:
	@files="$$(find cmd internal test -type f -name '*.go' -print)"; \
		unformatted="$$(test -z "$$files" || gofmt -l $$files)"; \
		test -z "$$unformatted" || { printf 'gofmt required:\n%s\n' "$$unformatted" >&2; exit 1; }

tidy:
	$(GO) mod tidy

tidy-check:
	$(GO) mod tidy -diff

vet:
	$(GO) vet ./...

lint:
	@command -v staticcheck >/dev/null 2>&1 || { \
		printf '%s\n' 'staticcheck is required: go install honnef.co/go/tools/cmd/staticcheck@v0.6.1' >&2; \
		exit 1; \
	}
	staticcheck ./...

test: test-go test-rpm test-edge

# Keep active compatibility packages gated; exclude only the retired V1 harness.
test-go:
	@packages="$$( $(GO) list ./... | grep -Ev '/internal/cli$$' )"; \
		$(GO) test -timeout '$(TEST_TIMEOUT)' -count=1 $$packages

test-rpm:
	cd third_party/cavaliergopher-rpm && $(GO) test -count=1 ./...

test-edge:
	@command -v npm >/dev/null 2>&1 || { printf '%s\n' 'npm is required for edge tests' >&2; exit 1; }
	cd edge && npm run build && npm test

test-core:
	$(GO) test -timeout '$(CORE_TEST_TIMEOUT)' -count=1 $(CORE_PACKAGES)

test-v2: test-core

race:
	$(GO) test -race -timeout '$(RACE_TIMEOUT)' -count=1 $(CORE_PACKAGES)

check: fmt-check tidy-check vet lint test-core

clean-delivery:
	test/compat/test-clean-delivery.sh '$(CLEAN_DELIVERY_OUT)'

goreleaser-check:
	@command -v '$(GORELEASER)' >/dev/null 2>&1 || { \
		printf '%s\n' 'goreleaser is required: https://goreleaser.com/install/' >&2; \
		exit 1; \
	}
	SOW_VERSION='$(VERSION)' $(GORELEASER) check

release-local: goreleaser-check
	SOW_VERSION='$(VERSION)' $(GORELEASER) release --snapshot --clean --skip=publish
	@printf 'local GoReleaser artifacts: %s\n' '$(DIST_DIR)'

release:
	@$(MAKE) check
	@$(MAKE) test
	@$(MAKE) race
	@$(MAKE) clean-delivery
	@$(MAKE) release-local
	@printf 'SOW v%s release gates passed\n' '$(VERSION)'

clean: clean-bin clean-dist

clean-bin:
	@test '$(BIN_DIR)' = '$(ROOT_DIR)/bin'
	rm -rf -- '$(BIN_DIR)'

clean-dist:
	@test '$(DIST_DIR)' = '$(ROOT_DIR)/dist'
	rm -rf -- '$(DIST_DIR)'
