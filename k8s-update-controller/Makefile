.PHONY: build test clean docker-build

# Version from git or default to "dev"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Binary name
BINARY = k8s-update-controller

# Docker image (consistent with other components)
IMAGE_NAME ?= k8s-update-controller
IMAGE_TAG ?= latest
REGISTRY ?= ghcr.io/bvboe/b2s-go

# Build the binary
build:
	@echo "Building $(BINARY) version $(VERSION)..."
	CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION)" -o $(BINARY) .

# Run tests
test:
	@echo "Running tests..."
	go test -v -race ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY)
	go clean

# Build Docker image
docker-build:
	@echo "Building Docker image $(IMAGE_NAME):$(IMAGE_TAG)..."
	cd .. && docker build -f k8s-update-controller/Dockerfile --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run locally (requires kubeconfig)
run: build
	@echo "Running $(BINARY)..."
	./$(BINARY)

# Install dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run ./...

.DEFAULT_GOAL := build
