# k8s-scan-server

A Kubernetes-based scanning server for bjorn2scan v2. This is the initial prototype implementing a simple HTTP service with health and info endpoints.

## Overview

The k8s-scan-server is designed to run inside a Kubernetes cluster and will eventually handle container and workload scanning. This initial version provides:

- `/health` endpoint - Returns HTTP 200 OK for health checks
- `/info` endpoint - Returns JSON with version, pod name, and namespace information

## Prerequisites

- Go 1.25 or later
- Docker
- kubectl
- Helm 3.x (for Helm deployments)
- A Kubernetes cluster (kind, minikube, or remote cluster)

## Building

### Build the Go binary locally

```bash
make build
```

### Build the Docker image

```bash
make docker-build
```

You can customize the image name and tag:

```bash
make docker-build IMAGE_NAME=myregistry/k8s-scan-server IMAGE_TAG=v0.1.0
```

## Running Locally

Run the binary directly:

```bash
./k8s-scan-server
```

The server will start on port 8080. Test it:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/info
```

## Deploying to Kubernetes

Deployment is done using the Helm chart (named `bjorn2scan`).

### Lint the Helm chart

```bash
make helm-lint
```

### Preview the rendered templates

```bash
make helm-template
```

### Deploy to kind

```bash
make helm-kind-deploy
```

This will:
1. Build the Docker image
2. Load it into your kind cluster
3. Install or upgrade the Helm release
4. Create the namespace if it doesn't exist

### Deploy to minikube

```bash
make helm-minikube-deploy
```

### Install/Upgrade the Helm chart

```bash
# Fresh install
make helm-install

# Upgrade existing release
make helm-upgrade
```

You can customize the installation:

```bash
make helm-install IMAGE_NAME=myregistry/k8s-scan-server IMAGE_TAG=v0.1.0 NAMESPACE=bjorn2scan HELM_RELEASE=my-scanner
```

### Uninstall the Helm release

```bash
make helm-uninstall
```

### Customize Helm values

Edit `helm/bjorn2scan/values.yaml` or provide your own values file:

```bash
helm install bjorn2scan ./helm/bjorn2scan -f my-values.yaml
```

## Testing the Deployment

Once deployed, you can test the service:

```bash
# Port-forward to access the service
kubectl port-forward svc/k8s-scan-server 8080:8080

# In another terminal
curl http://localhost:8080/health
curl http://localhost:8080/info
```

Or exec into the pod:

```bash
# Get the pod name first
kubectl get pods -n default

# Exec into it (adjust the pod name)
kubectl exec -it <pod-name> -n default -- sh
```

## Project Structure

```
k8s-scan-server/
├── main.go              # HTTP server implementation
├── Dockerfile           # Multi-stage Docker build using Wolfi
├── Makefile            # Build and deployment automation
├── helm/               # Helm chart
│   └── bjorn2scan/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── serviceaccount.yaml
│           ├── _helpers.tpl
│           └── NOTES.txt
└── README.md           # This file
```

## Testing

### Unit Tests

Run unit tests locally:
```bash
make test
```

### Integration Tests

Integration tests verify the application works correctly when deployed to Kubernetes.

**Run all tests locally (Recommended):**
```bash
# From repository root
./scripts/test_local
```
This comprehensive script runs:
- Unit tests
- golangci-lint
- Docker build
- Helm lint and template
- Full integration tests on both kind and minikube
- Automatic cleanup

**Run against already deployed service:**
```bash
# Set SERVICE_URL if not using default (localhost:8080)
export SERVICE_URL=http://localhost:8080
make integration-test
```

**Run full integration test on kind:**
```bash
make integration-test-kind
```
This will: build image → create kind cluster → deploy with Helm → run tests → cleanup

**Run full integration test on minikube:**
```bash
make integration-test-minikube
```

Integration tests verify:
- `/health` endpoint returns 200 OK
- `/info` endpoint returns valid JSON with version, pod name, and namespace
- Service responds within timeout
- 404 handling for non-existent endpoints

## CI/CD

The project uses GitHub Actions for continuous integration and releases.

### CI Workflow

Runs on every push to `main` and on pull requests:

- **Test & Build**: Compiles Go code, runs tests with race detection and coverage
- **Lint**: Runs golangci-lint for code quality checks and gosec for Go security issues
- **Docker Build**: Builds Docker image and scans with Grype for vulnerabilities
- **Helm Lint**: Validates and templates the Helm chart

### Integration Test Workflow

Runs on every push to `main` and on pull requests:

- **Tests on kind**: Full integration test suite on kind cluster
- **Tests on minikube**: Full integration test suite on minikube cluster
- **Reusable workflow**: Test pipeline defined once, runs on both cluster types

### Security Scanners

The project uses multiple security scanners to ensure code and container quality:

- **gosec**: Go-specific security scanner that checks for common security issues
- **Grype**: Container image vulnerability scanner (from Anchore)
- **golangci-lint**: Code quality and best practices linting

### Dependency Management

**Dependabot** automatically monitors and updates dependencies:

- **Go modules**: k8s-scan-server and integration tests
- **GitHub Actions**: Workflow dependencies
- **Docker images**: Base image updates (Wolfi)
- **Schedule**: Weekly updates every Monday at 3:00 AM
- **Grouping**: Minor and patch updates are grouped to reduce PR noise
- **Labels**: PRs are automatically labeled by dependency type

Dependabot PRs trigger CI/CD pipelines including integration tests, ensuring updates don't break functionality.

### Release Workflow

Triggered when pushing a tag (e.g., `v0.1.0`):

1. **Runs integration tests on both kind and minikube** (release only proceeds if tests pass)
2. Runs full unit test suite
3. Builds multi-architecture Docker images (AMD64 & ARM64)
4. Pushes images to GitHub Container Registry (`ghcr.io`)
5. Signs container images with cosign (sigstore)
6. Packages Helm chart with version from tag
7. Pushes Helm chart as OCI artifact to GitHub Container Registry
8. Signs Helm chart with cosign (sigstore)
9. Generates SBOM (Software Bill of Materials) using Syft
10. Creates GitHub release with chart and SBOM attached
11. Scans released images with Grype for vulnerabilities

### Creating a Release

```bash
# Tag the release
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# GitHub Actions will automatically:
# - Build and push multi-arch images
# - Sign the images
# - Create a GitHub release
# - Attach the Helm chart
```

### Using Released Artifacts

**Install from OCI registry (Recommended):**

```bash
# Install Helm chart directly from OCI registry
helm install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --version 0.1.0 \
  --namespace bjorn2scan \
  --create-namespace
```

**Install from downloaded chart:**

```bash
# Download bjorn2scan-0.1.0.tgz from GitHub release page
helm install bjorn2scan ./bjorn2scan-0.1.0.tgz \
  --namespace bjorn2scan \
  --create-namespace
```

**Pull container image:**

```bash
docker pull ghcr.io/<owner>/<repo>/k8s-scan-server:0.1.0
```

### Verifying Signatures

**Container Images:**

Released container images are signed with cosign (sigstore):

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/k8s-scan-server:0.1.0
```

**Helm Charts:**

Released Helm charts (OCI artifacts) are also signed with cosign:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.0
```

### GPG Commit Signing

To sign your commits with GPG:

1. **Generate a GPG key** (if you don't have one):
   ```bash
   gpg --full-generate-key
   # Use RSA, 4096 bits, no expiration (or set expiration as preferred)
   ```

2. **Configure Git to use GPG**:
   ```bash
   # List your GPG keys
   gpg --list-secret-keys --keyid-format=long

   # Configure git with your key ID
   git config --global user.signingkey <YOUR_KEY_ID>
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true
   ```

3. **Add your GPG key to GitHub**:
   ```bash
   # Export your public key
   gpg --armor --export <YOUR_KEY_ID>
   ```
   Then add it at: https://github.com/settings/keys

4. **Sign commits and tags**:
   ```bash
   # Commits are now automatically signed
   git commit -m "Your commit message"

   # Create signed tags
   git tag -s v0.1.0 -m "Release v0.1.0"
   ```

## Development

The Makefile provides several targets to streamline development:

**Build & Test:**
- `make help` - Show available targets
- `make build` - Build locally
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make docker-build` - Build Docker image

**Deployment:**
- `make helm-lint` - Lint the Helm chart
- `make helm-template` - Preview rendered templates
- `make helm-kind-deploy` - Quick deploy to kind
- `make helm-minikube-deploy` - Quick deploy to minikube
- `make helm-install` - Install Helm chart
- `make helm-upgrade` - Upgrade Helm release
- `make helm-uninstall` - Uninstall Helm release

## Next Steps

This is a hello service prototype. Future iterations will add:

- Container discovery in the Kubernetes cluster
- SBOM generation using Syft
- Vulnerability scanning using Grype
- Data persistence (sqlite/boltdb)
- OpenTelemetry metrics
- Web UI

## License

Same as bjorn2scan v1.
