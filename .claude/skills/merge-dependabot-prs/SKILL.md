---
name: merge-dependabot-prs
description: Analyze and merge open Dependabot pull requests with testing and user confirmation before committing
---

# Merge Dependabot PRs

Analyze and integrate open Dependabot pull requests into the codebase with proper testing and user confirmation before committing.

## Workflow

### Step 1: Discover Open PRs

List all open Dependabot pull requests:

```bash
gh pr list --state open --author "app/dependabot" --json number,title,headRefName,updatedAt
```

If no PRs are found, also check for any PRs with "dependabot" in the branch name:

```bash
gh pr list --state open --json number,title,headRefName,author
```

### Step 2: Categorize and Detect Patterns

Group the PRs by type:
- **Go dependencies**: PRs updating `go.mod`/`go.sum` files
- **NPM dependencies**: PRs updating `package.json`/`package-lock.json` files
- **GitHub Actions**: PRs updating `.github/workflows/` files
- **Security updates**: PRs with "security" in the title or marked as security fixes

**Detect monorepo patterns:**
- Check if multiple PRs update the **same dependency** in different modules (e.g., multiple PRs for `github.com/anchore/syft`)
- This is common in monorepos with multiple Go modules (scanner-core, k8s-scan-server, pod-scanner, bjorn2scan-agent)
- Pattern: `bump <package> from X.Y.Z to A.B.C in /module-name`

**Note on tidy failures:**
- Dependabot PRs in monorepos often show `tidy: FAILURE` in CI checks
- This is **expected behavior** - Dependabot updates one module at a time, causing inconsistencies across modules
- Don't let tidy failures block merging - they'll be resolved by the manual update process

### Step 3: Analyze Each PR

For each PR, analyze:

1. **Check PR status and mergability**:
   ```bash
   gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus,statusCheckRollup
   ```

2. **Review the changes**:
   ```bash
   gh pr diff <PR_NUMBER>
   ```

3. **Check for breaking changes**:
   - Look for major version bumps (e.g., v1.x.x to v2.x.x)
   - Check release notes for breaking changes
   - Identify if the dependency is direct or indirect

4. **Check for conflicts**:
   - If multiple PRs update the same file, they may conflict
   - Prioritize security updates and major dependency groups

### Step 4: Merge Strategy

**Choose the appropriate strategy based on the PR pattern:**

#### Strategy A: Individual PR Merge (single module updates)

**For mergeable PRs without conflicts that update only one module:**
```bash
gh pr merge <PR_NUMBER> --merge --delete-branch
```

#### Strategy B: Manual Monorepo Update (recommended for multi-module updates)

**When multiple PRs update the same dependency across different modules:**

This is the **preferred approach** for monorepos to avoid conflicts and tidy failures.

1. **Identify the target version** from any of the PRs (e.g., `v1.42.3`)

2. **Update all affected modules manually:**
   ```bash
   # For each module that needs the update:
   cd scanner-core && go get <package>@<version> && go mod tidy && cd ..
   cd k8s-scan-server && go get <package>@<version> && go mod tidy && cd ..
   cd pod-scanner && go get <package>@<version> && go mod tidy && cd ..
   cd bjorn2scan-agent && go get <package>@<version> && go mod tidy && cd ..
   ```

3. **Close all related Dependabot PRs** with a comment:
   ```bash
   gh pr close <PR_NUMBER> --comment "Closed in favor of manual update across all modules to maintain consistency. Updated in commit <commit-hash>."
   ```

**Why this approach?**
- Updates all modules atomically to the same version
- Avoids cross-module dependency conflicts
- Resolves tidy failures automatically
- More efficient than merging 4+ individual PRs
- Also updates transitive dependencies consistently

#### Strategy C: Manual Resolution (conflicts or breaking changes)

**For PRs with conflicts or requiring code changes:**
1. Pull the latest main branch
2. Manually update the dependency
3. Make necessary code changes to accommodate breaking changes
4. Close the PR with a comment explaining the resolution

#### Strategy D: Language runtime / toolchain upgrades

Dependabot watches `require` lines. It does **not** watch the `go` directive,
and it cannot see the Go standard library at all — so an entire class of
advisories is invisible to it. Go 1.26.8 carried **13 stdlib advisories**
(HTTP/2 memory exhaustion, HTTP/1 connection desync after CONNECT i.e. request
smuggling, MIME memory-limit bypass, unbounded `Range` header parsing,
`html/template` context bugs, `crypto/tls` ECH) and no PR mentioned any of them.
They surfaced only because an OSV sweep of `x/net` listed `1.26.9` among its
fixed versions, which prompted querying the `stdlib` package directly.

**Always check the stdlib, every cycle:**

```bash
# the go directive per module
for m in scanner-core sbom-generator-shared k8s-scan-server pod-scanner \
         bjorn2scan-agent k8s-update-controller; do
  printf "%-22s %s\n" "$m" "$(grep -E '^go ' $m/go.mod | awk '{print $2}')"
done

# advisories against that version
curl -s "https://api.osv.dev/v1/query" -X POST \
  -d '{"package":{"name":"stdlib","ecosystem":"Go"},"version":"1.26.8"}' \
  | jq -r '.vulns[]? | "\(.id): \(.summary)\n   fixed: \([.affected[]?.ranges[]?.events[]?.fixed]|unique|map(select(.!=null))|join(", "))"'
```

Raise the directive with `go -C <module> get go@<version>`. Note that HTTP/2
issues typically live in **both** `golang.org/x/net` and the stdlib, so they
need the module bump *and* the toolchain bump — fixing only one leaves the
other exposed.

**The directive is a security control, so CI must honour it.** This is where it
went wrong on 986dab6 and broke CI in 5524851:

```
go: go.mod requires go >= 1.26.9 (running go 1.26.8; GOTOOLCHAIN=local)
```

Two traps, both of which were assumed away rather than checked:

1. **`go-version: '1.26'` does not reliably mean "latest 1.26.x".** 1.26.9 was
   in `actions/go-versions` and marked stable, yet setup-go resolved 1.26.8 on
   that run — a race with the manifest or tool cache. Any dependency on a
   floating minor resolving to a specific patch is a race.
2. **`actions/setup-go` sets `GOTOOLCHAIN=local`**, which disables Go's
   automatic toolchain download. So a directive above the installed toolchain
   is a hard build failure, not a silent upgrade. Do not assume Go will fetch
   what go.mod asks for.

**Therefore: every `actions/setup-go` step must use `go-version-file`, never a
bare `go-version`.** This makes go.mod the single source of truth so the two
can never drift:

```yaml
# reusable workflows — reuse the component-path input
- uses: actions/setup-go@v7
  with:
    go-version-file: ${{ inputs.component-path }}/go.mod

# workflows spanning several modules — name the governing module
- uses: actions/setup-go@v7
  with:
    go-version-file: k8s-scan-server/go.mod
```

For multi-module workflows the referenced go.mod **must be the one with the
highest directive** among the modules that workflow builds, or the same failure
recurs. Verify after any directive change:

```bash
grep -rn "go-version" .github/workflows/   # expect zero bare go-version
actionlint
```

Raising a **library's** directive (e.g. `sbom-generator-shared`) is a
compatibility decision, not a security one: it ships no binary, and MVS already
gives consumers the higher floor. Leave it unless there's a reason.

### Step 5: Run Tests

After merging or making manual changes, run the full test suite:

**Build all components:**
```bash
make build-all
```

**Run tests for each module:**
```bash
make -C k8s-scan-server test
make -C pod-scanner test
make -C k8s-update-controller test
make -C bjorn2scan-agent test
```

**For scanner-core (note: integration tests may be slow due to Grype DB):**
```bash
cd scanner-core && go test -v -short ./...
```

### Step 6: Handle Test Failures

If tests fail after dependency updates:

1. **Identify the breaking change** by reviewing:
   - Error messages
   - Changed API signatures
   - Deprecated function usage

2. **Make necessary code changes**:
   - Update API calls to match new library versions
   - Fix deprecated function usage
   - Update type definitions if needed

3. **Re-run tests** to verify fixes

### Step 7: Run Linters (If Code Changed)

If any code changes were made (not just dependency updates), run linters before committing:

**Go modules** - run golangci-lint from within each module directory:
```bash
cd k8s-scan-server && golangci-lint run ./...
cd pod-scanner && golangci-lint run ./...
cd k8s-update-controller && golangci-lint run ./...
cd bjorn2scan-agent && golangci-lint run ./...
cd scanner-core && golangci-lint run ./...
```

**NPM/Web** - run web linting:
```bash
cd scanner-core/web && npm run lint
```

Fix any linting errors before proceeding to commit.

### Step 8: Commit Changes (User Confirmation Required)

**IMPORTANT: Always ask the user before committing any changes.**

Present a clear summary:
- **Dependency**: Package name and version change (e.g., `syft 1.42.2 → 1.42.3`)
- **Modules affected**: List of modules updated (e.g., all 4 Go modules)
- **Transitive dependencies**: Note if other packages were updated (e.g., "20+ transitive deps")
- **Test results**: All builds passed, all tests passed, no lint errors
- **Strategy used**: Manual update / PR merge / Manual with code changes

Ask: "Would you like me to commit these changes?"

If approved, commit with an appropriate message:

**For manual monorepo updates:**
```bash
git add go.mod go.sum */go.mod */go.sum
git commit -m "chore(deps): bump <package> from X.Y.Z to A.B.C

Updated across all modules: scanner-core, k8s-scan-server, pod-scanner, bjorn2scan-agent

Also updated <N> transitive dependencies including:
- <notable-dep-1>
- <notable-dep-2>

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

**For individual PR merges:**
```bash
# No manual commit needed - PR merge commits automatically
```

**For manual updates with code changes:**
```bash
git add <all-affected-files>
git commit -m "chore(deps): bump <package> from X.Y.Z to A.B.C

- Updated code to accommodate breaking changes
- <Brief description of code changes>

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

### Step 9: Cancel Redundant CI Runs

Each commit pushed to `main` and each `gh pr merge` triggers a fresh CI run.
When you process multiple Dependabot PRs back-to-back (Strategy B commit + several
Strategy A merges), GitHub will queue a full CI pipeline for every single one —
even though the latest commit already contains all prior changes.

**After the last merge, list in-flight runs and cancel everything except the
latest commit's:**

```bash
# See what's running
gh run list --limit 15 --json databaseId,status,headSha,name,displayTitle \
  | jq -r '.[] | select(.status == "queued" or .status == "in_progress")
            | "\(.databaseId)\t\(.headSha[0:7])\t\(.name)\t\(.displayTitle[0:55])"'

# Cancel each redundant run by ID
gh run cancel <run-id>
```

**Rule of thumb:** keep only the runs whose `headSha` matches `git rev-parse HEAD`
on `origin/main`. Earlier-commit runs are superseded — their outcome is already
captured by the latest run, which exercises the cumulative state.

**Even better: bake this into the workflows** so future pushes auto-cancel.
Add a `concurrency` block to each long-running workflow:

```yaml
concurrency:
  group: <workflow-name>-${{ github.ref }}
  cancel-in-progress: true
```

Confirmed working in `ci.yaml`, `agent-integration-test.yaml`, and
`auto-update-test.yaml` (added 2026-05-11). Once those are in place you generally
won't need to cancel by hand — pushing the next commit handles it.

Also verify path filters are tight: a `paths: ['scanner-core/**']` filter will
match `scanner-core/web/**` and trigger Go CI on web-only NPM updates. Use
`!scanner-core/web/**` exclusions inside `paths`, not `paths-ignore` (GitHub
silently drops `paths-ignore` when `paths` is present in the same event block).

## Error Handling

### Common Issues

1. **Tidy failures in CI (EXPECTED in monorepos)**:
   - Status: `tidy: FAILURE` in CI checks
   - **This is normal** - Dependabot updates one module at a time
   - **Solution**: Use Strategy B (Manual Monorepo Update) to update all modules together
   - Don't try to fix by merging individual PRs - this will cascade failures

2. **PR not mergeable due to other CI failures**:
   - Check the CI status: `gh pr checks <PR_NUMBER>`
   - Review failed checks and determine if they're related to the update
   - Common: build failures, test failures (may need code changes)

3. **Multiple PRs for same dependency (monorepo pattern)**:
   - Example: 4 PRs updating `github.com/anchore/syft` in different modules
   - **Solution**: Use Strategy B (Manual Monorepo Update)
   - Close all PRs after manual update with explanatory comment

4. **Conflicting PRs (different dependencies)**:
   - Merge PRs in order of importance (security first, then by age)
   - Use `@dependabot rebase` comment to rebase remaining PRs after each merge

5. **Breaking API changes**:
   - Search for usage of the updated package: `rg "package\.Function"`
   - Review the package's changelog/release notes
   - Make minimal code changes to restore compatibility
   - Re-run tests to verify fixes

## Notes

- This skill is designed for the bjorn2scan monorepo structure with multiple Go modules
- **Prefer Strategy B (Manual Monorepo Update)** when multiple PRs update the same dependency
- Tidy failures in Dependabot PRs are **expected** in monorepos - don't let them block progress
- The scanner-core integration tests may timeout due to Grype DB downloads - this is expected
- Always preserve the existing commit style and conventions
- Manual updates across all modules ensure consistency and avoid dependency conflicts
- **The PRs are a starting point, not the scope.** Four of the last five cycles
  turned up advisories no PR mentioned — grpc, otlploggrpc, x/crypto,
  containerd, x/net, and 13 in the Go stdlib. Always finish with a full OSV
  sweep (see Step 5) plus the stdlib check in Strategy D.
- **Verify versions AFTER `go mod tidy`, not after `go get`.** A `go get` on a
  package nothing else requires can be silently reverted by tidy. Commit
  14470f9 claimed `otlp 1.11.0 -> 1.11.1` when no go.mod line had changed,
  because the check happened before tidy.
- **Advisory data itself can be wrong and get corrected.** grpc 1.84.0 was
  reported as affected by CVE-2026-84445, prompting a deliberate downgrade to
  1.83.2; the advisory's ranges were corrected days later and 1.84.0 was never
  affected (only the `-dev` prereleases, which sort before the release). When a
  fix requires going *backwards*, re-check the advisory next cycle before
  treating the downgrade as permanent.
- **`go get` resolves upward only.** Downgrading a package can strand a
  transitive dependency ahead of what its parent supports — downgrading
  `containerd/v2` to 2.3.6 left `containerd/api` at 1.12.0 and the pairing
  would not compile. After any downgrade, check the siblings too.

## Decision Tree

**When you find Dependabot PRs, follow this decision process:**

1. **Single PR updating one module** → Use Strategy A (individual merge)
2. **Multiple PRs updating same dependency across modules** → Use Strategy B (manual update all modules)
3. **PR with tidy failures** → Check if it's a monorepo pattern, use Strategy B
4. **PR with build/test failures** → Investigate, may need code changes (Strategy C)
5. **PR with breaking changes (major version bump)** → Review changelog, update code (Strategy C)
6. **No PR at all, but the stdlib or `go` directive is behind** → Strategy D.
   Dependabot never raises this; check it every cycle regardless of what the
   PRs say. If you raise the directive, you must also confirm CI uses
   `go-version-file` or the build breaks.

**Example from this codebase:**
- Found 4 PRs: `syft 1.42.2 → 1.42.3` across scanner-core, k8s-scan-server, pod-scanner, bjorn2scan-agent
- All showed tidy failures (expected in monorepo)
- Used Strategy B: `go get github.com/anchore/syft@v1.42.3 && go mod tidy` in each module
- Result: All modules updated atomically, 20+ transitive deps updated, all tests passed
- Closed all 4 PRs with comment after committing manual update
