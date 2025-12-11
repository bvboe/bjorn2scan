# Bjørn2Scan Integration Tests

Comprehensive integration test suite for verifying Bjørn2Scan deployment on Kubernetes clusters.

## Prerequisites

- `kubectl` configured and connected to your cluster
- `helm` installed
- `jq` installed for JSON parsing
- `wget` available in the container images (already included)

## Quick Start

Run the test suite with default settings:

```bash
./integration-test/run-test
```

## Configuration

The test suite can be configured using environment variables:

```bash
# Test in a specific namespace (default: default)
NAMESPACE=bjorn2scan ./integration-test/run-test

# Specify Helm release name (default: bjorn2scan)
RELEASE_NAME=my-scanner ./integration-test/run-test

# Set timeout for operations (default: 300 seconds)
TIMEOUT=600 ./integration-test/run-test

# Set maximum wait time for scans to complete (default: 120 seconds)
# Note: Test will exit early if scans complete before timeout
SCAN_WAIT_TIME=180 ./integration-test/run-test
```

## Test Coverage

The integration test suite performs the following checks:

### 1. **Namespace Existence**
Verifies that the target namespace exists.

### 2. **Helm Release Status**
Checks that the Helm release is deployed and in the correct state.

### 3. **RBAC Configuration**
Validates ServiceAccount, ClusterRole, and ClusterRoleBinding are properly configured.

### 4. **Pod Status**
Verifies all pods are running and ready:
- pod-scanner (DaemonSet on all nodes)
- vulnerability-coordinator (Deployment)
- web-frontend (Deployment)

### 5. **Service Endpoints**
Checks that services have active endpoints:
- vulnerability-coordinator service
- web-frontend service

### 6. **Pod Scanner Health**
Tests the pod-scanner health endpoint on a running pod.

### 7. **Vulnerability Coordinator API**
Validates the vulnerability-coordinator endpoints:
- API health endpoint (`/api/hello`)
- Metrics endpoint (`/metrics`) is responding
- Note: This test verifies endpoints work, not that scans are complete (scan data is verified separately)

### 8. **Web Frontend Accessibility**
Verifies the web frontend service is responding with HTML content.
Note: Tests from vulnerability-coordinator pod since nginx container doesn't include wget/curl.

### 9. **Vulnerability Scan Data**
Polls for scans to complete (with configurable timeout) and validates:
- Containers are being scanned
- Vulnerability results are being generated
- Metrics are being exposed
- Exits early when scan data is detected (no need to wait full timeout)

### 10. **Pod Logs Error Check**
Reviews recent pod logs for error messages (non-blocking warnings).

## Example Output

```
======================================
Bjørn2Scan Integration Test Suite
======================================

[INFO] Testing deployment in namespace: default
[INFO] Release name: bjorn2scan

[INFO] Running test: Namespace Existence
[PASS] Namespace 'default' exists

[INFO] Running test: Helm Release Status
[PASS] Helm release 'bjorn2scan' is deployed

[INFO] Running test: RBAC Configuration
[PASS] ServiceAccount 'pod-scanner' exists
[PASS] ClusterRole 'pod-scanner-cluster-role' exists
[PASS] ClusterRoleBinding 'pod-scanner-cluster-role-binding' exists

[INFO] Running test: Pod Status
[PASS] pod-scanner: 3/3 pods ready
[PASS] vulnerability-coordinator: 1/1 pods ready
[PASS] web-frontend: 1/1 pods ready

...

======================================
Test Summary
======================================
[PASS] Tests passed: 23
[PASS] All tests passed!
```

## Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed

## Troubleshooting

### Test failures

If tests fail, check:

1. **Pod Status**: `kubectl get pods -n <namespace>`
2. **Pod Logs**: `kubectl logs -n <namespace> <pod-name>`
3. **Events**: `kubectl get events -n <namespace> --sort-by='.lastTimestamp'`

### Scan data not appearing

If scan data tests fail:
- Increase `SCAN_WAIT_TIME` for larger clusters (test polls every 5 seconds)
- Check pod-scanner has access to container runtime socket
- Verify pod-scanner is running on all nodes
- Check pod-scanner logs for scanning errors

### Permission issues

If RBAC tests fail:
- Verify ClusterRole has necessary permissions
- Check ClusterRoleBinding references correct ServiceAccount
- Review: `kubectl describe clusterrole pod-scanner-cluster-role`

## CI/CD Integration

Add to your CI/CD pipeline:

```yaml
# Example GitHub Actions
- name: Run Integration Tests
  run: |
    ./integration-test/run-test
  env:
    NAMESPACE: default
    RELEASE_NAME: bjorn2scan
    SCAN_WAIT_TIME: 180
```

## Manual Testing

For manual verification after the automated tests:

```bash
# Port-forward to web frontend
kubectl port-forward service/web-frontend 8080:80

# Open in browser
open http://localhost:8080

# Check metrics manually
kubectl port-forward service/vulnerability-coordinator 8081:80
curl http://localhost:8081/metrics
```
