# Claude Code Permissions

This document defines what Claude can do **WITHOUT asking for permission first** when working in this repository.

## ✅ YES - No Permission Needed

Claude can perform these operations freely:

### File Operations
- Read any file in the repository
- Edit/Write files (for requested code changes)
- Search codebase (Glob, Grep)
- Access to /tmp for storing temporary files

### Git (Read-Only)
- `git status`, `git diff`, `git log`, `git show`
- `git branch`, `git describe`, `git show-ref`, `git fetch`
- Any other read-only git commands

### GitHub CLI (Read-Only)
- `gh pr view`, `gh pr list`
- `gh issue list`, `gh issue view`
- `gh run list`, `gh run view`, `gh run watch`
- `gh api` (for read operations)
- `gh release view`, `gh release list`
- Any other read-only gh commands

### Build & Test
- `go build`, `go test`, `go vet`, `go mod tidy`, `go run`
- `make test`, `make build`, `make clean`
- `npm install`, `npm run lint`, `npm test`
- `./scripts/test-local` - Comprehensive local test suite
- `./scripts/test-k8s-update-controller` - K8s update controller integration tests
- `./scripts/test-agent-updater` - Agent auto-updater integration tests
- `./scripts/test-workflows-local` - Local workflow testing
- Any linting tools: `golangci-lint`, `yamllint`, `gofmt`

### Kubernetes
- **Read operations**: `kubectl get`, `kubectl describe`, `kubectl logs`
- **Write operations**: `kubectl apply`, `kubectl delete`, `kubectl restart`, `kubectl port-forward`, `kubectl exec`, etc.
- `helm lint`, `helm template`, `helm upgrade`, `helm uninstall`, `helm list`
- `kind load docker-image`

### Docker
- `docker build`, `docker run`, `docker tag`, `docker images`
- `docker exec`, `docker logs`, `docker system prune`
- Any other docker operations for local development

### SSH to 192.168.2.138
- Any operations related to managing and/or testing the bjorn2scan agent
- Installing, configuring, testing the agent
- Read and write operations are permitted

### Other Tools
- `curl`, `jq`, `grype`, `act`, `timeout`
- Process management: `ps`, `kill`, `pkill`, `lsof`
- File operations: `ls`, `cat`, `grep`, `find`, `chmod`, `scp`

## ❌ NO - Always Ask First

Claude **MUST ask permission** before performing these operations:

### Git Write Operations
- ❌ `git add` - Staging files is the user's responsibility
- ❌ `git commit` - Cannot create commits without explicit request
- ❌ `git tag` - Cannot create tags
- ❌ `git push` - Cannot push to remote
- ❌ `git rebase`, `git merge` - Cannot modify history
- ❌ `git checkout -b` - Can read branches but not create without asking
- ❌ Any other operation that modifies repository state

**Important**: The user reviews and stages/commits all changes. Claude's job is to make the file changes; the user's job is to add them to git.

### GitHub Operations
- ❌ `gh pr create` - Cannot create pull requests without request
- ❌ `gh release create`, `gh release delete` - Cannot manage releases
- ❌ Any write operations via GitHub CLI

### Destructive Operations
- ❌ Any operation that cannot be easily undone
- ❌ Operations that affect production systems (unless explicitly for testing)

## Guidelines

1. **When in doubt, it's in the YES category** - Prefer action over asking for permission for read operations and reversible changes
2. **The NO category is small and specific** - Only git/gh write operations and truly destructive actions require permission
3. **Context matters** - If the user explicitly asks for something in the NO category, do it (e.g., "create a commit with these changes")
4. **Be proactive** - Use the YES permissions freely to explore, test, and implement solutions

## Version
Last updated: 2025-12-22
