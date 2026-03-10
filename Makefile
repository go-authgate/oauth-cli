GO ?= go
EXECUTABLE := oauth-cli
GOFILES := $(shell find . -type f -name "*.go")
TAGS ?=

ifneq ($(shell uname), Darwin)
	EXTLDFLAGS = -extldflags "-static" $(null)
else
	EXTLDFLAGS =
endif

ifneq ($(DRONE_TAG),)
	VERSION ?= $(DRONE_TAG)
else
	VERSION ?= $(shell git describe --tags --always || git rev-parse --short HEAD)
endif
COMMIT ?= $(shell git rev-parse --short HEAD)

LDFLAGS ?=
## build: build the authgate binary
build: $(EXECUTABLE)

$(EXECUTABLE): $(GOFILES)
	$(GO) build -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o bin/$@ .

## install: install the authgate binary
install: $(GOFILES)
	$(GO) install -v -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)'

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## coverage: view test coverage in browser
coverage: test
	$(GO) tool cover -html=coverage.txt

## install-golangci-lint: install golangci-lint if not present
install-golangci-lint:
	@command -v golangci-lint >/dev/null 2>&1 || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin v2.7.2

## fmt: format go files using golangci-lint
fmt: install-golangci-lint
	golangci-lint fmt

## lint: run golangci-lint to check for issues
lint: install-golangci-lint
	golangci-lint run

## build_linux_amd64: build the authgate binary for linux amd64
build_linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/amd64/$(EXECUTABLE) .

## build_linux_arm64: build the authgate binary for linux arm64
build_linux_arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -a -tags '$(TAGS)' -ldflags '$(EXTLDFLAGS)-s -w $(LDFLAGS)' -o release/linux/arm64/$(EXECUTABLE) .

## clean: remove build artifacts and test coverage
clean:
	rm -rf bin/ release/ coverage.txt

## rebuild: clean and build
rebuild: clean build

.PHONY: help build install test coverage fmt lint clean rebuild
.PHONY: build_linux_amd64 build_linux_arm64
.PHONY: install-golangci-lint mod-download mod-tidy mod-verify check-tools version

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## mod-download: download go module dependencies
mod-download:
	$(GO) mod download

## mod-tidy: tidy go module dependencies
mod-tidy:
	$(GO) mod tidy

## mod-verify: verify go module dependencies
mod-verify:
	$(GO) mod verify

## check-tools: verify required tools are installed
check-tools:
	@command -v $(GO) >/dev/null 2>&1 || (echo "Go not found" && exit 1)
	@command -v golangci-lint >/dev/null 2>&1 || echo "golangci-lint not installed (run: make install-golangci-lint)"

## version: display version information
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Go Version: $(shell $(GO) version)"
