.PHONY: help build build-all test clean docker-build docker-test install uninstall

# Variables
BINARY_NAME=bjorn2scan-agent
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -w -s"

# Build directories
BUILD_DIR=build
DIST_DIR=dist

# Multi-arch targets (Linux only)
PLATFORMS=linux/amd64 linux/arm64
DOCKER_IMAGE_NAME?=bjorn2scan-agent
IMAGE_TAG?=latest

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build binary for current platform
	@echo "Building $(BINARY_NAME) v$(VERSION) for current platform..."
	go build $(LDFLAGS) -v -o $(BINARY_NAME) .

build-all: clean ## Build binaries for all platforms (Linux amd64, arm64)
	@echo "Building $(BINARY_NAME) v$(VERSION) for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} ; \
		output="$(DIST_DIR)/$(BINARY_NAME)-$${GOOS}-$${GOARCH}" ; \
		echo "Building for $${GOOS}/$${GOARCH}..." ; \
		GOOS=$${GOOS} GOARCH=$${GOARCH} CGO_ENABLED=0 go build $(LDFLAGS) -o $${output} . ; \
		mv $${output} $(DIST_DIR)/$(BINARY_NAME) ; \
		tar -czf $(DIST_DIR)/$(BINARY_NAME)-$${GOOS}-$${GOARCH}.tar.gz -C $(DIST_DIR) $(BINARY_NAME) ; \
		rm $(DIST_DIR)/$(BINARY_NAME) ; \
		if command -v sha256sum >/dev/null 2>&1; then \
			(cd $(DIST_DIR) && sha256sum $(BINARY_NAME)-$${GOOS}-$${GOARCH}.tar.gz > $(BINARY_NAME)-$${GOOS}-$${GOARCH}.tar.gz.sha256) ; \
		else \
			(cd $(DIST_DIR) && shasum -a 256 $(BINARY_NAME)-$${GOOS}-$${GOARCH}.tar.gz > $(BINARY_NAME)-$${GOOS}-$${GOARCH}.tar.gz.sha256) ; \
		fi ; \
	done
	@echo "Build complete! Artifacts in $(DIST_DIR)/"
	@ls -lh $(DIST_DIR)/

test: ## Run tests
	go test -v -race ./...

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR) $(DIST_DIR)

docker-build: ## Build Docker image for testing
	docker build -t $(DOCKER_IMAGE_NAME):$(IMAGE_TAG) .

docker-test: docker-build ## Run agent in Docker container for testing
	@echo "Starting $(BINARY_NAME) in Docker..."
	@echo "Access at: http://localhost:9999/health"
	@echo "Press Ctrl+C to stop"
	docker run --rm -p 9999:9999 --name $(DOCKER_IMAGE_NAME)-test $(DOCKER_IMAGE_NAME):$(IMAGE_TAG)

install: build ## Install binary to /usr/local/bin (requires sudo)
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo install -m 755 $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Install complete! Run: $(BINARY_NAME)"

uninstall: ## Uninstall binary from /usr/local/bin (requires sudo)
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstall complete!"
