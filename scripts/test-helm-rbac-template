#!/usr/bin/env bash
# Validate that the Helm chart ClusterRole template has all required permissions
# This test runs WITHOUT a Kubernetes cluster - it just validates the template

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="$SCRIPT_DIR/helm/bjorn2scan"
FAILED_TESTS=0
PASSED_TESTS=0

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++)) || true
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++)) || true
}

echo "========================================"
echo "Helm Chart RBAC Template Validation"
echo "Chart: $CHART_DIR"
echo "========================================"
echo ""

# Generate the rendered template
print_test "Rendering Helm template with updateController enabled"
RENDERED=$(helm template test "$CHART_DIR" --set updateController.enabled=true 2>/dev/null)

if [ $? -eq 0 ]; then
    print_pass "Helm template rendered successfully"
else
    print_fail "Failed to render Helm template"
    exit 1
fi

# Extract ClusterRole from rendered template
CLUSTERROLE=$(echo "$RENDERED" | awk '/^kind: ClusterRole$/,/^---$/')

if [ -z "$CLUSTERROLE" ]; then
    print_fail "ClusterRole not found in rendered template"
    exit 1
fi

print_pass "ClusterRole found in template"

echo ""
echo "=== Validating Required Permissions ==="

# Function to check if a resource and verb exist in the ClusterRole
check_permission() {
    local resource=$1
    local verb=$2
    local apigroup=${3:-'""'}

    # Look for the resource in the ClusterRole (match with or without quotes)
    if echo "$CLUSTERROLE" | grep -q "\"$resource\""; then
        # Check if the verb exists in the same rule (within next 10 lines)
        if echo "$CLUSTERROLE" | grep -A 10 "\"$resource\"" | grep -q "\"$verb\""; then
            print_pass "ClusterRole has $verb permission for $resource (apiGroup: $apigroup)"
            return 0
        else
            print_fail "ClusterRole missing $verb permission for $resource (apiGroup: $apigroup)"
            return 1
        fi
    else
        print_fail "ClusterRole missing resource: $resource"
        return 1
    fi
}

# Core resources (apiGroup: "")
check_permission "configmaps" "get"
check_permission "configmaps" "list"
check_permission "configmaps" "watch"
check_permission "configmaps" "create"
check_permission "configmaps" "update"
check_permission "configmaps" "patch"  # CRITICAL: This was missing
check_permission "configmaps" "delete"

check_permission "secrets" "get"
check_permission "secrets" "patch"
check_permission "secrets" "delete"

# Apps resources (apiGroup: "apps")
check_permission "deployments" "get"
check_permission "deployments" "update"
check_permission "deployments" "patch"

check_permission "daemonsets" "get"
check_permission "daemonsets" "patch"

# CRITICAL: ReplicaSets permission (this was the bug!)
print_test "Checking for replicasets resource (CRITICAL)"
if echo "$CLUSTERROLE" | grep -q "\"replicasets\""; then
    print_pass "ClusterRole includes replicasets resource"
    check_permission "replicasets" "get"
    check_permission "replicasets" "list"
    check_permission "replicasets" "watch"
else
    print_fail "ClusterRole MISSING replicasets resource - Helm upgrades will FAIL!"
    echo -e "${RED}This is a critical bug! Update helm/bjorn2scan/templates/clusterrole.yaml${NC}"
    ((FAILED_TESTS++))
fi

# Batch resources (apiGroup: "batch")
check_permission "cronjobs" "get"
check_permission "cronjobs" "patch"
check_permission "jobs" "get"
check_permission "jobs" "list"

# Service resources
check_permission "services" "get"
check_permission "services" "patch"
check_permission "serviceaccounts" "get"
check_permission "persistentvolumeclaims" "get"

# RBAC resources (apiGroup: "rbac.authorization.k8s.io")
check_permission "clusterroles" "get"
check_permission "clusterroles" "patch"
check_permission "clusterrolebindings" "get"
check_permission "clusterrolebindings" "patch"

echo ""
echo "=== Validating Template Structure ==="

# Check that updateController permissions are conditional
print_test "Checking if update-controller permissions are conditional"
if grep -q "{{- if .Values.updateController.enabled }}" "$CHART_DIR/templates/clusterrole.yaml"; then
    print_pass "Update-controller permissions are properly gated"
else
    print_fail "Update-controller permissions should be conditional on updateController.enabled"
fi

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ Helm chart RBAC template is correct!${NC}"
    exit 0
else
    echo -e "${RED}✗ Helm chart RBAC template has issues!${NC}"
    echo ""
    echo "Fix the ClusterRole template at: helm/bjorn2scan/templates/clusterrole.yaml"
    echo ""
    echo "Required fixes:"
    echo "1. Add 'patch' verb to configmaps resources"
    echo "2. Add 'replicasets' to apps apiGroup resources list"
    echo "3. Ensure all Helm upgrade operations have necessary permissions"
    exit 1
fi
