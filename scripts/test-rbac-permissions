#!/usr/bin/env bash
# Test script to validate RBAC permissions for update-controller
# This ensures the service account has all necessary permissions for Helm upgrades

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${TEST_NAMESPACE:-b2sv2}"
SERVICE_ACCOUNT="bjorn2scan"
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

# Test if a permission exists
test_permission() {
    local verb=$1
    local resource=$2
    local apigroup=${3:-""}
    local namespace_flag=""

    if [ -n "$4" ]; then
        namespace_flag="-n $4"
    fi

    local resource_with_group="$resource"
    if [ -n "$apigroup" ]; then
        resource_with_group="$resource.$apigroup"
    fi

    print_test "Testing: $verb $resource_with_group"

    if kubectl auth can-i "$verb" "$resource_with_group" \
        --as="system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}" \
        $namespace_flag &>/dev/null; then
        print_pass "Can $verb $resource_with_group"
        return 0
    else
        print_fail "Cannot $verb $resource_with_group"
        return 1
    fi
}

echo "========================================"
echo "RBAC Permission Tests for Update Controller"
echo "Namespace: $NAMESPACE"
echo "ServiceAccount: $SERVICE_ACCOUNT"
echo "========================================"
echo ""

echo "=== Core Resource Permissions ==="
# ConfigMaps (Helm release data)
test_permission "get" "configmaps" "" "$NAMESPACE"
test_permission "list" "configmaps" "" "$NAMESPACE"
test_permission "watch" "configmaps" "" "$NAMESPACE"
test_permission "create" "configmaps" "" "$NAMESPACE"
test_permission "update" "configmaps" "" "$NAMESPACE"
test_permission "patch" "configmaps" "" "$NAMESPACE"
test_permission "delete" "configmaps" "" "$NAMESPACE"

# Secrets (Helm release data)
test_permission "get" "secrets" "" "$NAMESPACE"
test_permission "list" "secrets" "" "$NAMESPACE"
test_permission "create" "secrets" "" "$NAMESPACE"
test_permission "update" "secrets" "" "$NAMESPACE"
test_permission "patch" "secrets" "" "$NAMESPACE"
test_permission "delete" "secrets" "" "$NAMESPACE"

echo ""
echo "=== Apps API Group (Deployments, DaemonSets, ReplicaSets) ==="
# Deployments
test_permission "get" "deployments" "apps" "$NAMESPACE"
test_permission "list" "deployments" "apps" "$NAMESPACE"
test_permission "update" "deployments" "apps" "$NAMESPACE"
test_permission "patch" "deployments" "apps" "$NAMESPACE"

# DaemonSets
test_permission "get" "daemonsets" "apps" "$NAMESPACE"
test_permission "list" "daemonsets" "apps" "$NAMESPACE"
test_permission "update" "daemonsets" "apps" "$NAMESPACE"
test_permission "patch" "daemonsets" "apps" "$NAMESPACE"

# ReplicaSets (CRITICAL - Helm needs this!)
test_permission "get" "replicasets" "apps" "$NAMESPACE"
test_permission "list" "replicasets" "apps" "$NAMESPACE"
test_permission "watch" "replicasets" "apps" "$NAMESPACE"

echo ""
echo "=== Batch API Group (CronJobs, Jobs) ==="
test_permission "get" "cronjobs" "batch" "$NAMESPACE"
test_permission "list" "cronjobs" "batch" "$NAMESPACE"
test_permission "update" "cronjobs" "batch" "$NAMESPACE"
test_permission "patch" "cronjobs" "batch" "$NAMESPACE"

test_permission "get" "jobs" "batch" "$NAMESPACE"
test_permission "list" "jobs" "batch" "$NAMESPACE"

echo ""
echo "=== Service Resources ==="
test_permission "get" "services" "" "$NAMESPACE"
test_permission "list" "services" "" "$NAMESPACE"
test_permission "update" "services" "" "$NAMESPACE"
test_permission "patch" "services" "" "$NAMESPACE"

test_permission "get" "serviceaccounts" "" "$NAMESPACE"
test_permission "list" "serviceaccounts" "" "$NAMESPACE"

echo ""
echo "=== Storage Resources ==="
test_permission "get" "persistentvolumeclaims" "" "$NAMESPACE"
test_permission "list" "persistentvolumeclaims" "" "$NAMESPACE"
test_permission "update" "persistentvolumeclaims" "" "$NAMESPACE"

echo ""
echo "=== RBAC Resources (Cluster-wide) ==="
test_permission "get" "clusterroles" "rbac.authorization.k8s.io"
test_permission "list" "clusterroles" "rbac.authorization.k8s.io"
test_permission "update" "clusterroles" "rbac.authorization.k8s.io"
test_permission "patch" "clusterroles" "rbac.authorization.k8s.io"

test_permission "get" "clusterrolebindings" "rbac.authorization.k8s.io"
test_permission "list" "clusterrolebindings" "rbac.authorization.k8s.io"
test_permission "update" "clusterrolebindings" "rbac.authorization.k8s.io"
test_permission "patch" "clusterrolebindings" "rbac.authorization.k8s.io"

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ All RBAC permissions are correct!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some RBAC permissions are missing!${NC}"
    echo ""
    echo "To fix, ensure helm/bjorn2scan/templates/clusterrole.yaml has all required permissions."
    exit 1
fi
