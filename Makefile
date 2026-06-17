.PHONY: help build-all test-all docker-build-all clean-all helm-lint helm-template helm-install helm-upgrade helm-uninstall helm-kind-deploy helm-kind-deploy-with-metrics helm-minikube-deploy

# Variables
# If NAMESPACE is not set, the scripts will auto-detect from kubectl context
# Set explicitly with: make target NAMESPACE=custom-namespace
NAMESPACE?=
HELM_RELEASE?=bjorn2scan
HELM_CHART=./helm/bjorn2scan
SCAN_SERVER_IMAGE?=ghcr.io/bvboe/b2s-go/k8s-scan-server
POD_SCANNER_IMAGE?=ghcr.io/bvboe/b2s-go/pod-scanner
UPDATE_CONTROLLER_IMAGE?=ghcr.io/bvboe/b2s-go/k8s-update-controller
# Use timestamp for local builds to ensure unique tags (evaluated once and exported)
IMAGE_TAG:=$(if $(IMAGE_TAG),$(IMAGE_TAG),local-$(shell date +%s))
export IMAGE_TAG

# Enable Docker BuildKit for faster builds with cache mounts
export DOCKER_BUILDKIT=1

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'

build-all: ## Build all Go binaries
	@echo "Building all components..."
	$(MAKE) -C k8s-scan-server build
	$(MAKE) -C pod-scanner build
	$(MAKE) -C k8s-update-controller build
	$(MAKE) -C bjorn2scan-agent build

test-all: ## Run tests for all components
	@echo "Running tests for all components..."
	$(MAKE) -C sbom-generator-shared test
	$(MAKE) -C scanner-core test
	$(MAKE) -C k8s-scan-server test
	$(MAKE) -C pod-scanner test
	$(MAKE) -C k8s-update-controller test
	$(MAKE) -C bjorn2scan-agent test

build-agent-release: ## Build bjorn2scan-agent release binaries for all platforms
	@echo "Building bjorn2scan-agent release binaries..."
	$(MAKE) -C bjorn2scan-agent build-all

docker-build-all: ## Build all Docker images
	@echo "Building all Docker images..."
	$(MAKE) -C k8s-scan-server docker-build IMAGE_NAME=$(SCAN_SERVER_IMAGE) IMAGE_TAG=$(IMAGE_TAG)
	$(MAKE) -C pod-scanner docker-build IMAGE_NAME=$(POD_SCANNER_IMAGE) IMAGE_TAG=$(IMAGE_TAG)
	$(MAKE) -C k8s-update-controller docker-build IMAGE_NAME=$(UPDATE_CONTROLLER_IMAGE) IMAGE_TAG=$(IMAGE_TAG)

clean-all: ## Clean all build artifacts
	@echo "Cleaning all build artifacts..."
	$(MAKE) -C sbom-generator-shared clean
	$(MAKE) -C scanner-core clean
	$(MAKE) -C k8s-scan-server clean
	$(MAKE) -C pod-scanner clean
	$(MAKE) -C k8s-update-controller clean
	$(MAKE) -C bjorn2scan-agent clean

# Helm targets
helm-lint: ## Lint the Helm chart
	@echo "Linting Helm chart..."
	helm lint $(HELM_CHART)

helm-template: ## Render Helm templates locally
	@echo "Rendering Helm templates..."
	helm template $(HELM_RELEASE) $(HELM_CHART) --namespace $(NAMESPACE)

helm-install: helm-lint ## Install the Helm chart
	@echo "Installing Helm chart $(HELM_RELEASE) to namespace $(NAMESPACE)..."
	helm install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
		--set scanServer.image.tag=$(IMAGE_TAG) \
		--set scanServer.image.pullPolicy=IfNotPresent \
		--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
		--set podScanner.image.tag=$(IMAGE_TAG) \
		--set podScanner.image.pullPolicy=IfNotPresent \
		--set updateController.image.tag=$(IMAGE_TAG)

helm-upgrade: ## Upgrade the Helm release
	@echo "Upgrading Helm release $(HELM_RELEASE) in namespace $(NAMESPACE)..."
	helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
		--set scanServer.image.tag=$(IMAGE_TAG) \
		--set scanServer.image.pullPolicy=IfNotPresent \
		--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
		--set podScanner.image.tag=$(IMAGE_TAG) \
		--set podScanner.image.pullPolicy=IfNotPresent \
		--set updateController.image.tag=$(IMAGE_TAG)
	@echo "Rolling out restart to pick up new images..."
	kubectl rollout restart deployment/$(HELM_RELEASE)-scan-server -n $(NAMESPACE)
	kubectl rollout restart daemonset/$(HELM_RELEASE)-pod-scanner -n $(NAMESPACE)

helm-uninstall: ## Uninstall the Helm release
	@echo "Uninstalling Helm release $(HELM_RELEASE) from namespace $(NAMESPACE)..."
	helm uninstall $(HELM_RELEASE) --namespace $(NAMESPACE)

# Quick Helm deploy for kind (build all + load all + install/upgrade)
helm-kind-deploy: docker-build-all ## Build and deploy to kind
	$(eval DEPLOY_NAMESPACE := $(or $(NAMESPACE),$(shell kubectl config view --minify --output 'jsonpath={..namespace}'),default))
	@echo "============================================"
	@echo "Deploying to kind with image tag: $(IMAGE_TAG)"
	@echo "Namespace: $(DEPLOY_NAMESPACE)"
	@echo "============================================"
	@echo "Loading images into kind cluster..."
	kind load docker-image $(SCAN_SERVER_IMAGE):$(IMAGE_TAG)
	kind load docker-image $(POD_SCANNER_IMAGE):$(IMAGE_TAG)
	kind load docker-image $(UPDATE_CONTROLLER_IMAGE):$(IMAGE_TAG)
	@if helm list -n $(DEPLOY_NAMESPACE) | grep -q $(HELM_RELEASE); then \
		helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(DEPLOY_NAMESPACE) \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Kind Cluster"; \
		kubectl rollout restart deployment/$(HELM_RELEASE)-scan-server -n $(DEPLOY_NAMESPACE); \
		kubectl rollout restart daemonset/$(HELM_RELEASE)-pod-scanner -n $(DEPLOY_NAMESPACE); \
	else \
		helm install $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(DEPLOY_NAMESPACE) \
			--create-namespace \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Kind Cluster"; \
	fi
	@echo "============================================"
	@echo "Deployment complete!"
	@echo "Image tag used: $(IMAGE_TAG)"
	@echo "Check status: kubectl get pods -n $(DEPLOY_NAMESPACE)"
	@echo "View logs: kubectl logs -l app.kubernetes.io/name=bjorn2scan -n $(DEPLOY_NAMESPACE)"
	@echo "Port forward: kubectl port-forward svc/$(HELM_RELEASE) 8080:80 -n $(DEPLOY_NAMESPACE)"
	@echo "============================================"

# Deploy with Prometheus/Grafana and OTEL metrics on kind
helm-kind-deploy-with-metrics: docker-build-all ## Build and deploy to kind with Prometheus and OTEL metrics
	$(eval DEPLOY_NAMESPACE := $(or $(NAMESPACE),$(shell kubectl config view --minify --output 'jsonpath={..namespace}'),default))
	@echo "============================================"
	@echo "Deploying to namespace: $(DEPLOY_NAMESPACE)"
	@echo "============================================"
	@echo "Deploying Prometheus and Grafana with OTEL support"
	@bash ./dev-local/kind-dasboard-otel.sh $(DEPLOY_NAMESPACE)
	@echo ""
	@echo "============================================"
	@echo "Deploying bjorn2scan with OTEL metrics enabled"
	@echo "Image tag: $(IMAGE_TAG)"
	@echo "============================================"
	@echo "Loading images into kind cluster..."
	kind load docker-image $(SCAN_SERVER_IMAGE):$(IMAGE_TAG)
	kind load docker-image $(POD_SCANNER_IMAGE):$(IMAGE_TAG)
	kind load docker-image $(UPDATE_CONTROLLER_IMAGE):$(IMAGE_TAG)
	@if helm list -n $(DEPLOY_NAMESPACE) | grep -q $(HELM_RELEASE); then \
		helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(DEPLOY_NAMESPACE) \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Kind Cluster" \
			--set scanServer.config.otelMetrics.enabled=true \
			--set scanServer.config.otelMetrics.endpoint="prometheus-kube-prometheus-prometheus.$(DEPLOY_NAMESPACE).svc.cluster.local:9090" \
			--set scanServer.config.otelMetrics.protocol="http" \
			--set scanServer.config.otelMetrics.pushInterval="1m" \
			--set scanServer.config.otelMetrics.insecure=true; \
		kubectl rollout restart deployment/$(HELM_RELEASE)-scan-server -n $(DEPLOY_NAMESPACE); \
		kubectl rollout restart daemonset/$(HELM_RELEASE)-pod-scanner -n $(DEPLOY_NAMESPACE); \
	else \
		helm install $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(DEPLOY_NAMESPACE) \
			--create-namespace \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Kind Cluster" \
			--set scanServer.config.otelMetrics.enabled=true \
			--set scanServer.config.otelMetrics.endpoint="prometheus-kube-prometheus-prometheus.$(DEPLOY_NAMESPACE).svc.cluster.local:9090" \
			--set scanServer.config.otelMetrics.protocol="http" \
			--set scanServer.config.otelMetrics.pushInterval="1m" \
			--set scanServer.config.otelMetrics.insecure=true; \
	fi
	@echo ""
	@echo "============================================"
	@echo "Deployment complete!"
	@echo "============================================"
	@echo "Image tag used: $(IMAGE_TAG)"
	@echo "Namespace: $(DEPLOY_NAMESPACE)"
	@echo ""
	@echo "Bjorn2scan:"
	@echo "  Check status: kubectl get pods -n $(DEPLOY_NAMESPACE)"
	@echo "  View logs: kubectl logs -l app.kubernetes.io/name=bjorn2scan -n $(DEPLOY_NAMESPACE)"
	@echo ""
	@echo "Port Forwarding:"
	@echo "  Bjorn2scan UI:"
	@echo "    kubectl port-forward svc/$(HELM_RELEASE) 8080:80 -n $(DEPLOY_NAMESPACE)"
	@echo "    Then open: http://localhost:8080"
	@echo ""
	@echo "  Prometheus UI:"
	@echo "    kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n $(DEPLOY_NAMESPACE)"
	@echo "    Then open: http://localhost:9090"
	@echo "    Query: bjorn2scan_deployment"
	@echo ""
	@echo "  Grafana UI:"
	@echo "    kubectl port-forward svc/prometheus-grafana 3000:80 -n $(DEPLOY_NAMESPACE)"
	@echo "    Then open: http://localhost:3000"
	@echo "    Login: admin / prom-operator"
	@echo "============================================"

# Quick Helm deploy for minikube (build all + load all + install/upgrade)
helm-minikube-deploy: docker-build-all ## Build and deploy to minikube
	@echo "============================================"
	@echo "Deploying to minikube with image tag: $(IMAGE_TAG)"
	@echo "============================================"
	@echo "Loading images into minikube..."
	minikube image load $(SCAN_SERVER_IMAGE):$(IMAGE_TAG)
	minikube image load $(POD_SCANNER_IMAGE):$(IMAGE_TAG)
	minikube image load $(UPDATE_CONTROLLER_IMAGE):$(IMAGE_TAG)
	@if helm list -n $(NAMESPACE) | grep -q $(HELM_RELEASE); then \
		helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(NAMESPACE) \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Minikube Cluster"; \
		kubectl rollout restart deployment/$(HELM_RELEASE)-scan-server -n $(NAMESPACE); \
		kubectl rollout restart daemonset/$(HELM_RELEASE)-pod-scanner -n $(NAMESPACE); \
	else \
		helm install $(HELM_RELEASE) $(HELM_CHART) \
			--namespace $(NAMESPACE) \
			--create-namespace \
			--set scanServer.image.repository=$(SCAN_SERVER_IMAGE) \
			--set scanServer.image.tag=$(IMAGE_TAG) \
			--set scanServer.image.pullPolicy=IfNotPresent \
			--set podScanner.image.repository=$(POD_SCANNER_IMAGE) \
			--set podScanner.image.tag=$(IMAGE_TAG) \
			--set podScanner.image.pullPolicy=IfNotPresent \
			--set updateController.image.tag=$(IMAGE_TAG) \
			--set clusterName="Minikube Cluster"; \
	fi
	@echo "============================================"
	@echo "Deployment complete!"
	@echo "Image tag used: $(IMAGE_TAG)"
	@echo "Check status: kubectl get pods -n $(NAMESPACE)"
	@echo "View logs: kubectl logs -l app.kubernetes.io/name=bjorn2scan -n $(NAMESPACE)"
	@echo "Port forward: kubectl port-forward svc/$(HELM_RELEASE) 8080:80 -n $(NAMESPACE)"
	@echo "============================================"
