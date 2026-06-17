# bjorn2scan v2 (b2s-go) — Claude Code Guide

## Project Context

This is bjorn2scan v2, a Go-based Kubernetes and host vulnerability scanner.
See DEVELOPMENT.md for full architecture and setup details.

**Core philosophy:**
- Build incrementally. Don't build everything at once.
- Keep solutions simple. Start minimal; let the user ask for more complexity.
- **If asked for options, present the options and STOP. Do NOT start implementing.**
  Wait for explicit approval before writing any code.
- Be concise and to the point.

## Architecture

6 separate Go modules, each with their own `go.mod`. There is no Go workspace
(`go.work`) — modules are independent.

### Module dependency graph

```
scanner-core          (no internal deps — core library)
sbom-generator-shared (no internal deps — SBOM shared library)

k8s-scan-server       → scanner-core
bjorn2scan-agent      → scanner-core, sbom-generator-shared
pod-scanner           → sbom-generator-shared only (NOT scanner-core)
k8s-update-controller (no internal deps)
```

**These dependency relationships must not be changed without deep analysis and
explicit permission.** In particular: do not add `scanner-core` as a dependency
of `pod-scanner` or `k8s-update-controller`, and do not move code between
modules, without being explicitly asked to do so.

## Permissions

Full details in CLAUDE_PERMISSIONS.md. Key points:

- **Git commits**: Never commit without explicit user request. The user stages and commits.
- **Helm chart versions**: Never bump `version` fields — they are managed by the release process.
- **Build, test, lint**: Run freely without asking.
- **File renames**: Always use `git mv`, never rename by copying.
- **File writes**: Always use Edit over Write for existing files. Never overwrite a file without reading it first.

## Debugging Kubernetes Issues

When debugging K8s problems, **use kubectl first** — don't grep local files:

1. `kubectl get pods -n b2sv2` — check pod status and restart counts
2. `kubectl logs -n b2sv2 deploy/bjorn2scan-scan-server` — check logs
3. `kubectl describe pod -n b2sv2 <pod>` — check events and resource issues
4. Check Helm values and env vars **before** assuming a build or packaging issue

Common misdiagnosis to avoid: attributing missing functionality to Docker caching
or `.dockerignore` when the real cause is a disabled Helm flag
(e.g., `hostScanning.enabled=false`) or a missing environment variable.

## Testing Workflow

Always run in this order after making code changes:

```bash
# 1. Build everything
make build-all

# 2. Run tests
make test-all
# For scanner-core with slow integration tests, use:
cd scanner-core && go test -short ./...

# 3. Lint — golangci-lint is required
cd <module> && golangci-lint run ./...

# 4. Integration test (deploy to local Kind cluster)
make helm-kind-deploy
```

Never skip linting. `golangci-lint` catches issues (unused imports, unhandled errors,
etc.) that a simple format check will not.

### errcheck in defers

`golangci-lint` with `errcheck` requires handling errors from `defer` calls:

```go
// Wrong — errcheck will fail:
defer rows.Close()

// Correct:
defer func() {
    if err := rows.Close(); err != nil {
        log.Error("failed to close rows", "error", err)
    }
}()
```

### Migration Tests

Database migration tests must use **realistic populated data**, not empty databases.
Migration bugs often only trigger when rows exist in the tables being migrated.
Always populate test data before running migration tests.

## Code Style

- Keep it simple. If a solution feels complex, it probably is.
- No unnecessary abstractions or config options for one-off cases.
- When presenting options, clearly label each (Option A, Option B) with distinct
  descriptions. Never blend options together.
- No silent assumptions about versions, package names, or environment details —
  verify from source files or ask.

## Commit Style

Conventional commits: `type(scope): description`

Examples:
- `feat(nodes): add rescan-nodes scheduled job`
- `fix(metrics): stream node vulnerability metrics to prevent OOM`
- `chore(deps): bump github.com/anchore/syft from 1.42.2 to 1.42.3`
- `refactor(database): simplify GetScannedNodes query`

## Dependency Updates (Dependabot / Go modules)

This is a monorepo with multiple Go modules. When Dependabot opens multiple PRs for
the same package (one per module), use the manual approach instead:

```bash
cd scanner-core     && go get <package>@<version> && go mod tidy && cd ..
cd k8s-scan-server  && go get <package>@<version> && go mod tidy && cd ..
cd pod-scanner      && go get <package>@<version> && go mod tidy && cd ..
cd bjorn2scan-agent && go get <package>@<version> && go mod tidy && cd ..
```

`tidy: FAILURE` in Dependabot CI is **expected** in monorepos — don't let it block.

## Database Migrations

Migrations live in `scanner-core/database/migrations.go` as incremental versioned
entries. Always add new migrations as the next sequential version number. Never
modify existing migrations.

## Release Summaries

When generating a release summary from commits, use this structure:

```markdown
## Highlights
[2-3 sentence summary of the most important changes]

## What's Changed

### Features
### Bug Fixes
### Testing
### Documentation
### Internal

## Statistics
- X commits by Y contributors
- Z files changed
```

## Common Shorthand

- **"Check github"** — look at the CI run results for the latest push (`gh run list` / `gh run view`)
- **"It's already committed"** — the user already committed; don't try to commit again
- **"Roll that back"** — revert the recent changes, the approach was wrong

## Interaction Style

- When a tool call is rejected, **stop and wait** — don't proceed with an alternative approach.
- When the user pastes terminal output (build errors, kubectl output, logs), read it and fix the specific issue directly.
- Don't summarize what you just did at the end of a response.

## Reference

- `TODO.md` — active tasks and backlog (always edit, never overwrite)
- `DEVELOPMENT.md` — full architecture, setup, and development guide
- `CLAUDE_PERMISSIONS.md` — detailed permissions reference
- `dev-local/` — local investigation notes and test results
