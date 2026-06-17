Goals of the project:
We're making a reimplementation of https://github.com/bvboe/bjorn2scan/. Bjørn2Scan served as a great proof of concept
that proved out the following concepts:
* It's possible to scan containers on the host they're running wihout downloading them from the source repository
* It's possible to track what workloads are running on the Kubernetes cluster and keep the scan data up to date
* It's possible to apply a similar scanning approach to the hosts themselves
* There's a ton of value in aggregating the data and using OpenTelemetry to share the data with Prometheus / Grafana
* The combination of Syft and Grype was particularly valuable for collecting the SBOM, storing it and
  analyzing it on a regular basis.
* The web UI was simple, but very effective
* We've learned a lot about how ContainerD and Docker works under the hood
* Helm works great for deploying to Kubernetes

The approach also had some weaknesses:
* The choice of usig Python as a programming language enabled rapid development, but also had some big
  limitations
* No unit testing made some designs feel like trial and error, and the integration testing is limited
* We ran into performance limitations for large datasets
* Aggregation of data was tricky
* The integration between vulnerability coordinator and scanners felt kind of flimsy, but it worked(!)
* We don't know how well this approach scales in larger clusters
* Security is not a first class citizen

We'll therefore do a complete reimplementation where we'll take the lessons learned and do it in a better way. We do
not just copy things from the old implementation. We build this gradually and reassess all implementation choices
to make sure it's working according to our requirements. This among others means the following will be important:
* We will be build two kinds of scanners: One to be deployed on a Kubernetes cluster, similar to what version I did.
  We'll also do an agent based implementation that is to be deployed directly on a host, scan the host itself
  and whatever containers that are running on the host.
* We'll be building the application using Go. The code needs to be modular, so that the same code can go into the
  Kubernetes scanner, as well as the agent scanner, even though the way they will be deployed is completely different.
* Testing is important. We'll be using test driven development whenever it makes sense, and integration testing.
* Proper CI/CD and release management is important from day 1.
* It's important to have a securely defined deployment
* Enable reuse of code, and externalize configuration whenever needed. We don't duplicate code. Ever!
* Developer productivity is key. We'll have a challenge as the developer desktop is on macOS, while the application
  will be running on Linux based containers / hosts. The applications will be very dependent on the environment
  they get deployed into, so containers will be very useful for supporting the development environment. We'll
  also need scripts to support rapid local deployment.
* We'll be leveraging Kind and MiniKube for testing locally on the desktop, as well as for integration testing.
* Whatever testing we'll be doing in the CI/CD pipeline should also be executable from a developer desktop.
* Whatever containers we're building will be using Wolfi.
* Use sigstore to sign build artefacts
* The web UI will be served as static html, supported by css and JavaScript. This means we have the choice between 
  using nginx to serve the pages or have the go application do the work.
* We'll need to support ARM64 and AMD64 based hardware.
* Given that we're building a scanner to look for software vulnerabilities, it's important that we keep our own
  infrastructure in order, and ship software with as few CVEs as possible. The Wolfi images are going to help
  but it also means keeping dependencies up-to-date is important, and we only hold off on upgrading dependencies
  if it introduces new vulnerabilities.

Project Context and Scope:
* This is Bjørn2Scan v2 - a continuation and evolution of the original project.
* Development will start in a separate GitHub repository, with the goal of eventually moving it over to the main
  Bjørn2Scan repository and retiring the old code in a separate branch.
* The project is released under the Apache License 2.0 (same as v1) — see [LICENSE](LICENSE).
* Target audience is broad (developers, DevOps engineers, security teams), but the primary users are expected to
  be security professionals.
* Success criteria:
  - First milestone: Good enough for use in a personal lab environment (multiple servers, Kubernetes clusters)
  - Longer term goal: Make it useful and robust enough for enterprise settings
* This is a solo project.
* Documentation and getting started guides are crucial and should be prioritized from day 1.
* The transition from v1 to v2 will be figured out over time. Preserving Helm compatibility would make transitions
  easier, but it's optional - it's acceptable to completely remove v1 before deploying v2 if needed.

A few important notes wrt the relationship between human and AI.
* Don't assume, ask!
* Don't try to build it all at the same time. There's a lot we don't know, and there are a lot of thigns
  to be figured out. That means it's important to build the system in small increments.
* If I ask for options or recommendations for how to solve a problem. Give me the options. Do not just go ahead
  and implement it. I should not have to yell STOP!
* Be concise and to the point. No need to brag about how smart I am.

---

# Development Guide

## Architecture Overview

The project consists of six Go modules — four deployable components and two shared libraries:

### 1. scanner-core (Go library)
- Core scanning logic shared between all deployments
- SBOM generation using Syft
- Vulnerability scanning using Grype
- Database operations (SQLite)
- Web UI (static HTML/CSS/JS)
- Package: `github.com/bvboe/b2s-go/scanner-core`

### 2. k8s-scan-server (Kubernetes deployment)
- Kubernetes controller/coordinator deployed as a pod
- Watches Kubernetes API for pods and containers
- Coordinates scanning activities
- Aggregates and stores scan results
- Serves web UI for cluster-wide visibility
- Package: `github.com/bvboe/b2s-go/k8s-scan-server`

### 3. pod-scanner (Kubernetes DaemonSet)
- Deployed as a DaemonSet (runs on every node)
- Retrieves SBOMs from pods running on each node
- Scans the node host filesystem (mounted at `/host`) when node scanning is enabled
- Works in conjunction with k8s-scan-server
- Package: `github.com/bvboe/b2s-go/pod-scanner`

### 4. bjorn2scan-agent (Standalone agent)
- Agent deployed directly on hosts (servers, VMs)
- Scans the host itself and any containers running on it
- Uses scanner-core for scanning logic
- Can be deployed on non-Kubernetes environments
- Package: `github.com/bvboe/b2s-go/bjorn2scan-agent`

### 5. sbom-generator-shared (Go library)
- Shared SBOM-generation library (Syft wrapper)
- Used by pod-scanner and bjorn2scan-agent
- No internal dependencies
- Package: `github.com/bvboe/b2s-go/sbom-generator-shared`

### 6. k8s-update-controller (Kubernetes deployment)
- In-cluster controller that auto-updates Bjørn2Scan components
- Watches for new releases and applies updated Helm charts
- Verifies cosign signatures before applying (see `docs/AUTO_UPDATE.md`)
- No internal dependencies
- Package: `github.com/bvboe/b2s-go/k8s-update-controller`

## Repository Structure

```
b2s-go/
├── scanner-core/          # Core scanning library (shared)
│   ├── database/         # SQLite database operations
│   ├── handlers/         # HTTP handlers for API
│   ├── static/          # Web UI (HTML/CSS/JS)
│   ├── go.mod           # Go module definition
│   └── ...
├── k8s-scan-server/      # Kubernetes controller
│   ├── k8s/             # Kubernetes client code
│   ├── go.mod           # Go module definition
│   └── ...
├── pod-scanner/          # Kubernetes DaemonSet scanner
│   ├── go.mod           # Go module definition
│   └── ...
├── bjorn2scan-agent/     # Standalone agent
│   ├── go.mod           # Go module definition
│   └── ...
├── sbom-generator-shared/ # Shared SBOM generation library
│   └── go.mod           # Go module definition
├── k8s-update-controller/ # In-cluster auto-update controller
│   └── go.mod           # Go module definition
├── helm/                 # Helm charts for deployment
│   └── bjorn2scan/
├── .github/workflows/    # GitHub Actions CI/CD
├── scripts/             # Development/test scripts
│   └── test-workflows-local  # Test GH Actions locally
├── TODO.md              # Persistent task tracking
├── CLAUDE_PERMISSIONS.md # AI assistant permissions
├── DEVELOPMENT.md       # This file
└── Makefile             # Build automation (see make help)
```

**Note:** Each component has its own go.mod file (separate Go modules), not a workspace.

## Local Development Setup

### Prerequisites
- Go 1.25+ (project uses Go 1.25)
- Docker Desktop (for building containers)
- kubectl (for Kubernetes deployments)
- Kind or Minikube (for local Kubernetes testing)
- Helm 3.x
- act (for testing GitHub Actions locally)

### Initial Setup
```bash
# Clone the repository
git clone https://github.com/bvboe/b2s-go.git
cd b2s-go

# Install dependencies for each module
cd scanner-core && go mod download && cd ..
cd k8s-scan-server && go mod download && cd ..
cd pod-scanner && go mod download && cd ..
cd bjorn2scan-agent && go mod download && cd ..

# Build all components
make build-all

# Run tests
make test-all
```

### Running Locally

**Scanner-core (standalone):**
```bash
cd scanner-core
go run .
```

**Kubernetes deployment (k8s-scan-server + pod-scanner in Kind):**
```bash
# Create Kind cluster
kind create cluster

# Build and deploy to Kind (builds images, loads them, installs with Helm)
make helm-kind-deploy

# Port-forward to access UI
kubectl port-forward svc/bjorn2scan 8080:8080

# Watch pods start
kubectl get pods -w
```

**Kubernetes deployment (Minikube):**
```bash
# Start Minikube
minikube start

# Build and deploy to Minikube
make helm-minikube-deploy

# Access the UI
minikube service bjorn2scan
```

**bjorn2scan-agent (on remote host):**
```bash
# Build for Linux
cd bjorn2scan-agent
GOOS=linux GOARCH=amd64 go build -o bjorn2scan-agent

# Copy to test host (192.168.2.138)
scp bjorn2scan-agent bjorn@192.168.2.138:/tmp/

# SSH and run
ssh bjorn@192.168.2.138
sudo /tmp/bjorn2scan-agent
```

## Testing

### Unit Tests
```bash
# Run all unit tests
go test ./...

# Run tests for specific package
go test ./scanner-core/database

# Run with coverage
go test -cover ./...
```

### Integration Tests
```bash
# Test workflows locally with act
./scripts/test-workflows-local

# Deploy to local Kind cluster and test
make helm-kind-deploy
# Then manually test the deployment
```

### GitHub Actions Testing
All CI/CD tests can be run locally:
```bash
# Validate workflow syntax
act -l

# Run specific workflow
act -W .github/workflows/ci.yaml
```

## Common Development Tasks

### Building

```bash
# Build all binaries
make build-all

# Build specific component
cd k8s-scan-server && go build

# Build all Docker images
make docker-build-all

# Build agent for all platforms (Linux AMD64/ARM64, macOS, Windows)
make build-agent-release

# Build multi-arch Docker image manually
docker buildx build --platform linux/amd64,linux/arm64 -t myimage:latest .
```

### Linting

```bash
# Run Go linter
golangci-lint run

# Run YAML linter
yamllint .github/workflows/

# Run all linters
make lint
```

### Updating Dependencies

```bash
# Update dependencies
go get -u ./...
go mod tidy

# Verify no new vulnerabilities
grype .
```

### Database Operations

```bash
# View database
sqlite3 scanner-core/scanner.db

# Reset database
rm scanner-core/scanner.db
```

## CI/CD Pipeline

The project uses GitHub Actions with reusable workflows:

- **go-component-reusable.yaml** - Build/test Go components with Docker
- **go-library-reusable.yaml** - Build/test Go libraries
- **go-binary-reusable.yaml** - Build/test standalone binaries
- **integration-test-reusable.yaml** - Run integration tests in Kind/Minikube

Key features:
- Caching for faster builds (Go modules, Docker layers, golangci-lint, Grype DB)
- Multi-arch builds (ARM64 + AMD64)
- Vulnerability scanning with Grype
- Container signing with cosign
- Helm chart validation

## Deployment

### Kubernetes (via Helm)

```bash
# Deploy to Kind/Minikube
helm install bjorn2scan ./helm/bjorn2scan

# Deploy with custom values
helm install bjorn2scan ./helm/bjorn2scan -f custom-values.yaml

# Upgrade deployment
helm upgrade bjorn2scan ./helm/bjorn2scan

# Uninstall
helm uninstall bjorn2scan
```

### Standalone Agent

```bash
# Build agent
cd bjorn2scan-agent
GOOS=linux GOARCH=amd64 go build -o bjorn2scan-agent

# Copy to host
scp bjorn2scan-agent bjorn@192.168.2.138:/usr/local/bin/

# Run on host
ssh bjorn@192.168.2.138
sudo bjorn2scan-agent
```

## Development Philosophy Reminders

- **Modular code**: scanner-core must work across k8s-scan-server, pod-scanner, and bjorn2scan-agent
- **No code duplication**: Reuse, don't copy
- **Test-driven**: Write tests for new functionality
- **Incremental development**: Small, working steps
- **Security first**: Keep dependencies updated, minimize CVEs
- **Developer productivity**: Scripts and containers for rapid iteration
- **Architecture**: k8s-scan-server coordinates, pod-scanner (DaemonSet) retrieves SBOMs from nodes

## Documentation References

- **TODO.md** - Current tasks and backlog
- **CLAUDE_PERMISSIONS.md** - What Claude Code can/cannot do
- **README.md** - Project overview and quick start
- **helm/bjorn2scan/README.md** - Helm chart documentation

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
lsof -ti:8080 | xargs kill
```

**Kind cluster issues:**
```bash
kind delete cluster
kind create cluster
```

**Docker build cache issues:**
```bash
docker builder prune
```

**Go module issues:**
```bash
go clean -modcache
go mod download
```
