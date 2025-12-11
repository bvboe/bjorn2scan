#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Usage
usage() {
    cat << EOF
Usage: $0 <version> [chart_version]

Create a new release of Bjørn2Scan using GitHub Actions.

Arguments:
  version         Version number (e.g., 1.0.0, 0.5.1)
                  DO NOT include 'v' prefix - it will be added automatically
  chart_version   Optional chart version (defaults to same as version)

Examples:
  $0 1.0.0              # Creates v1.0.0 release
  $0 0.5.1              # Creates v0.5.1 release
  $0 1.0.0 1.0.1        # App version 1.0.0, chart version 1.0.1

The script will:
  1. Validate the version format
  2. Check git status (must be on main, clean working tree)
  3. Trigger GitHub Actions release workflow
  4. Monitor the workflow execution
  5. Verify the release was created successfully

EOF
    exit 1
}

# Validate version format
validate_version() {
    local version=$1

    log_info "Validating version: $version"

    # Check if version is empty
    if [ -z "$version" ]; then
        log_error "Version cannot be empty"
        exit 1
    fi

    # Check if version starts with 'v' (including multiple v's)
    if [[ $version =~ ^v+ ]]; then
        log_error "Version MUST NOT include 'v' prefix: $version"
        log_error "This causes double 'v' in tags (v${version} becomes vv...)"
        log_info "❌ WRONG: $version"
        log_info "✅ CORRECT: ${version#v}"
        log_info "The workflow automatically adds 'v' prefix to create tags"
        exit 1
    fi

    # Check if version follows semver-ish format
    if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
        log_error "Invalid version format: $version"
        log_info "Expected format: X.Y.Z or X.Y.Z-suffix"
        log_info "Examples:"
        log_info "  ✅ 1.0.0"
        log_info "  ✅ 0.5.1"
        log_info "  ✅ 2.0.0-rc1"
        log_info "  ✅ 1.0.0-beta.1"
        log_info "  ❌ v1.0.0    (no 'v' prefix)"
        log_info "  ❌ 1.0       (must be X.Y.Z)"
        log_info "  ❌ 1.0.0.0   (only 3 components)"
        exit 1
    fi

    # Show what will be created
    log_info "This will create:"
    log_info "  • Git tag: v$version"
    log_info "  • GitHub release: v$version"
    log_info "  • Docker images: ...:$version"
    log_info "  • Helm chart: ...:$version"
    log_success "Version format is valid: $version"
}

# Check git status
check_git_status() {
    log_info "Checking git status..."

    # Check if in git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi

    # Check current branch
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$current_branch" != "main" ]; then
        log_error "Not on main branch (currently on: $current_branch)"
        log_info "Run: git checkout main"
        exit 1
    fi
    log_success "On main branch"

    # Check if working tree is clean
    if ! git diff-index --quiet HEAD --; then
        log_error "Working tree has uncommitted changes"
        log_info "Run: git status"
        exit 1
    fi
    log_success "Working tree is clean"

    # Pull latest changes
    log_info "Pulling latest changes from origin/main..."
    git fetch origin main

    local local_commit=$(git rev-parse HEAD)
    local remote_commit=$(git rev-parse origin/main)

    if [ "$local_commit" != "$remote_commit" ]; then
        log_warning "Local main is not up to date with origin/main"
        read -p "Pull latest changes? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git pull origin main
            log_success "Pulled latest changes"
        else
            log_error "Aborted by user"
            exit 1
        fi
    else
        log_success "Local main is up to date"
    fi
}

# Check if tag already exists
check_existing_tag() {
    local version=$1
    local tag="v$version"

    log_info "Checking if tag $tag already exists..."

    git fetch --tags

    if git rev-parse "$tag" >/dev/null 2>&1; then
        log_error "Tag $tag already exists"
        log_info "To delete: gh release delete $tag --yes && git push origin :refs/tags/$tag"
        exit 1
    fi

    log_success "Tag $tag does not exist"
}

# Trigger GitHub Actions workflow
trigger_release() {
    local version=$1
    local chart_version=$2

    log_info "Triggering GitHub Actions release workflow..."

    if [ -z "$chart_version" ]; then
        gh workflow run release.yml -f version="$version"
        log_info "Workflow triggered with version: $version"
    else
        gh workflow run release.yml -f version="$version" -f chart_version="$chart_version"
        log_info "Workflow triggered with version: $version, chart version: $chart_version"
    fi

    log_info "Waiting for workflow to start..."
    sleep 5
}

# Monitor workflow execution
monitor_workflow() {
    local version=$1

    log_info "Monitoring workflow execution..."

    # Get the latest workflow run
    local run_id=$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')

    if [ -z "$run_id" ]; then
        log_error "Could not find workflow run"
        exit 1
    fi

    log_info "Workflow run ID: $run_id"
    log_info "Watch at: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions/runs/$run_id"

    # Watch the workflow
    log_info "Watching workflow (this may take 10-15 minutes)..."
    if gh run watch "$run_id"; then
        log_success "Workflow completed successfully!"
        return 0
    else
        log_error "Workflow failed!"
        log_info "View logs: gh run view $run_id --log-failed"
        return 1
    fi
}

# Verify release
verify_release() {
    local version=$1
    local tag="v$version"

    log_info "Verifying release..."

    # Wait a moment for everything to sync
    sleep 5

    # Pull latest changes
    git fetch --tags
    git pull origin main --quiet

    # Check GitHub release
    log_info "Checking GitHub release..."
    if gh release view "$tag" >/dev/null 2>&1; then
        log_success "GitHub release $tag exists"
    else
        log_error "GitHub release $tag not found"
        return 1
    fi

    # Check git tag
    log_info "Checking git tag..."
    if git rev-parse "$tag" >/dev/null 2>&1; then
        log_success "Git tag $tag exists"
    else
        log_error "Git tag $tag not found"
        return 1
    fi

    # Check Chart.yaml
    log_info "Checking Chart.yaml..."
    local chart_version=$(grep "^version:" "$SCRIPT_DIR/bjorn2scan/Chart.yaml" | awk '{print $2}')
    local app_version=$(grep "^appVersion:" "$SCRIPT_DIR/bjorn2scan/Chart.yaml" | awk '{print $2}' | tr -d '"')

    if [ "$app_version" = "$version" ]; then
        log_success "Chart.yaml appVersion: $app_version"
    else
        log_error "Chart.yaml appVersion mismatch: expected $version, got $app_version"
        return 1
    fi

    # Check Docker Hub (pod-scanner as representative)
    log_info "Checking Docker Hub..."
    if curl -s "https://hub.docker.com/v2/repositories/bjornvb/k8s-pod-scanner/tags/$version" | grep -q '"name"'; then
        log_success "Docker Hub image tag $version exists"
    else
        log_error "Docker Hub image tag $version not found"
        return 1
    fi

    log_success "All release artifacts verified!"
}

# Show release summary
show_summary() {
    local version=$1
    local tag="v$version"

    echo ""
    echo "======================================"
    echo "Release Summary"
    echo "======================================"
    log_success "Release $tag created successfully!"
    echo ""
    echo "Docker Images:"
    echo "  - bjornvb/k8s-pod-scanner:$version"
    echo "  - bjornvb/k8s-scanner-vulnerability-coordinator:$version"
    echo "  - bjornvb/k8s-scanner-web-frontend:$version"
    echo ""
    echo "Helm Chart:"
    echo "  - oci://registry-1.docker.io/bjornvb/bjorn2scan:$(grep "^version:" "$SCRIPT_DIR/bjorn2scan/Chart.yaml" | awk '{print $2}')"
    echo ""
    echo "GitHub Release:"
    echo "  - https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/$tag"
    echo ""
    echo "Installation:"
    echo "  helm upgrade --install bjorn2scan oci://registry-1.docker.io/bjornvb/bjorn2scan --version $(grep "^version:" "$SCRIPT_DIR/bjorn2scan/Chart.yaml" | awk '{print $2}') --set clusterName=\"My Cluster\" --wait"
    echo ""
    echo "======================================"
}

# Main script
main() {
    # Check arguments
    if [ $# -lt 1 ]; then
        usage
    fi

    local version=$1
    local chart_version=${2:-}

    echo "======================================"
    echo "Bjørn2Scan Release Script"
    echo "======================================"
    echo ""

    # Run checks
    validate_version "$version"
    check_git_status
    check_existing_tag "$version"

    # Show final confirmation
    echo ""
    echo "======================================"
    log_warning "FINAL CONFIRMATION"
    echo "======================================"
    log_info "Creating release with:"
    log_info "  Version input: $version"
    log_info "  Will create tag: v$version"
    if [ -n "$chart_version" ]; then
        log_info "  Chart version: $chart_version"
    fi
    echo ""
    log_warning "This will:"
    log_info "  1. Run integration tests (~10 min)"
    log_info "  2. Build and push Docker images"
    log_info "  3. Create GitHub release v$version"
    log_info "  4. Update and commit Chart.yaml"
    echo ""
    read -p "Continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Aborted by user"
        exit 1
    fi

    # Create release
    trigger_release "$version" "$chart_version"

    if monitor_workflow "$version"; then
        if verify_release "$version"; then
            show_summary "$version"
            exit 0
        else
            log_error "Release verification failed"
            exit 1
        fi
    else
        log_error "Release workflow failed"
        exit 1
    fi
}

# Run main
main "$@"
