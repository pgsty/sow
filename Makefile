SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO ?= go
VERSION ?= 0.2.0
TEST_TIMEOUT ?= 60m
V2_TEST_TIMEOUT ?= 20m
RACE_TIMEOUT ?= 30m
ARGS ?=

ROOT_DIR := $(CURDIR)
BIN_DIR := $(ROOT_DIR)/bin
DIST_DIR := $(ROOT_DIR)/dist
BINARY := $(BIN_DIR)/sow
CLEAN_DELIVERY_OUT ?= $(if $(TMPDIR),$(TMPDIR),/tmp)/sow-clean-delivery
LDFLAGS := -s -w -X github.com/pgsty/sow/internal/v2cli.Version=$(VERSION)
V2_PACKAGES := ./internal/v2/... ./internal/v2cli ./internal/aptrepo ./internal/yumrepo

.PHONY: all help version build run install fmt fmt-check tidy tidy-check vet lint \
	test test-go test-rpm test-edge test-v2 race check clean-delivery dist \
	release clean clean-bin clean-dist

all: build

help:
	@printf '%s\n' \
		'SOW v$(VERSION)' \
		'' \
		'  make build           Build bin/sow for the current platform' \
		'  make run ARGS=...    Run the CLI from source (example: ARGS=version)' \
		'  make install         Install sow with the release version embedded' \
		'  make test            Run all Go modules and edge contract tests' \
		'  make test-v2         Run the focused SOW v0.2 package tests' \
		'  make race            Race-test the v0.2 core packages' \
		'  make check           Run format, module, vet, lint, and focused tests' \
		'  make clean-delivery  Rebuild and verify the deterministic source archive' \
		'  make dist            Cross-build four release binaries and SHA256SUMS' \
		'  make release         Run all release gates, then build dist/' \
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

test-go:
	$(GO) test -timeout '$(TEST_TIMEOUT)' -count=1 ./...

test-rpm:
	cd third_party/cavaliergopher-rpm && $(GO) test -count=1 ./...

test-edge:
	@command -v npm >/dev/null 2>&1 || { printf '%s\n' 'npm is required for edge tests' >&2; exit 1; }
	cd edge && npm run build && npm test

test-v2:
	$(GO) test -timeout '$(V2_TEST_TIMEOUT)' -count=1 $(V2_PACKAGES)

race:
	$(GO) test -race -timeout '$(RACE_TIMEOUT)' -count=1 $(V2_PACKAGES)

check: fmt-check tidy-check vet lint test-v2

clean-delivery:
	test/compat/test-clean-delivery.sh '$(CLEAN_DELIVERY_OUT)'

dist: clean-dist
	@mkdir -p '$(DIST_DIR)'
	@for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		os="$${target%/*}"; arch="$${target#*/}"; \
		output='$(DIST_DIR)'/sow_$(VERSION)_$${os}_$${arch}; \
		printf 'building %s/%s -> %s\n' "$$os" "$$arch" "$$output"; \
		CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" $(GO) build \
			-trimpath -ldflags '$(LDFLAGS)' -o "$$output" ./cmd/sow; \
		metadata="$$( $(GO) version -m "$$output" )"; \
		grep -Fq "GOOS=$$os" <<<"$$metadata"; \
		grep -Fq "GOARCH=$$arch" <<<"$$metadata"; \
	done
	@cd '$(DIST_DIR)' && if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum sow_* > SHA256SUMS; \
	else \
		shasum -a 256 sow_* > SHA256SUMS; \
	fi
	@printf 'release artifacts: %s\n' '$(DIST_DIR)'

release:
	@$(MAKE) check
	@$(MAKE) test
	@$(MAKE) race
	@$(MAKE) clean-delivery
	@$(MAKE) dist
	@printf 'SOW v%s release gates passed\n' '$(VERSION)'

clean: clean-bin clean-dist

clean-bin:
	@test '$(BIN_DIR)' = '$(ROOT_DIR)/bin'
	rm -rf -- '$(BIN_DIR)'

clean-dist:
	@test '$(DIST_DIR)' = '$(ROOT_DIR)/dist'
	rm -rf -- '$(DIST_DIR)'
