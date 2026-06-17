.PHONY: help build test clean docker-build

# Variables
BINARY_NAME=pod-scanner
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -w -s"
IMAGE_NAME?=pod-scanner
IMAGE_TAG?=latest

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go binary
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	go build $(LDFLAGS) -v -o $(BINARY_NAME) .

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)

docker-build: ## Build Docker image
	cd .. && docker build -f pod-scanner/Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG) --build-arg VERSION=$(VERSION) .
