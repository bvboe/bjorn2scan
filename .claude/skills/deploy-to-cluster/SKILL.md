---
name: deploy-to-cluster
description: Deploy test builds to microk8s/kubeadm clusters using harbor.cloudnative.biz/tmp registry
allowed-tools: Bash
---

# Deploy to Cluster

Deploy test builds of bjorn2scan to non-Kind Kubernetes clusters for testing.

## When to Use

- Testing changes on real clusters before release
- Debugging cluster-specific issues
- Validating fixes in production-like environments

## Usage

```
/deploy-to-cluster <cluster-context> <tag>
```

## Workflow

### Step 1: Determine Target Architecture

Before building, check the target cluster's architecture:

```bash
kubectl --context <CONTEXT> get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.architecture}{"\n"}{end}'
```

Common architectures:
- `amd64` - x86_64 (Intel/AMD)
- `arm64` - ARM 64-bit (Apple Silicon, Raspberry Pi 4, etc.)

### Step 2: Build Images for Target Architecture

**For amd64 clusters:**
```bash
docker buildx build --platform linux/amd64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-scan-server:<TAG> \
  -f k8s-scan-server/Dockerfile --push .

docker buildx build --platform linux/amd64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-pod-scanner:<TAG> \
  -f pod-scanner/Dockerfile --push .
```

**For arm64 clusters:**
```bash
docker buildx build --platform linux/arm64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-scan-server:<TAG> \
  -f k8s-scan-server/Dockerfile --push .

docker buildx build --platform linux/arm64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-pod-scanner:<TAG> \
  -f pod-scanner/Dockerfile --push .
```

**For multi-arch (both):**
```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-scan-server:<TAG> \
  -f k8s-scan-server/Dockerfile --push .

docker buildx build --platform linux/amd64,linux/arm64 \
  -t harbor.cloudnative.biz/tmp/bjorn2scan-pod-scanner:<TAG> \
  -f pod-scanner/Dockerfile --push .
```

### Step 3: Deploy via Helm

```bash
helm upgrade bjorn2scan ./helm/bjorn2scan \
  --kube-context <CONTEXT> \
  --namespace <NAMESPACE> \
  --set scanServer.image.repository=harbor.cloudnative.biz/tmp/bjorn2scan-scan-server \
  --set scanServer.image.tag=<TAG> \
  --set podScanner.image.repository=harbor.cloudnative.biz/tmp/bjorn2scan-pod-scanner \
  --set podScanner.image.tag=<TAG> \
  --reuse-values
```

### Step 4: Verify Deployment

```bash
# Check pods are using new images
kubectl --context <CONTEXT> get pods -n <NAMESPACE> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'

# Check pods are running
kubectl --context <CONTEXT> get pods -n <NAMESPACE>

# Check scan-server logs
kubectl --context <CONTEXT> logs -n <NAMESPACE> deploy/bjorn2scan-scan-server --tail=50
```

### Step 5: Get Service URL and Test

```bash
# Find service URL
kubectl --context <CONTEXT> get svc -n <NAMESPACE> bjorn2scan-scan-server -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
# Or for NodePort:
kubectl --context <CONTEXT> get svc -n <NAMESPACE> bjorn2scan-scan-server -o jsonpath='{.spec.ports[0].nodePort}'

# Check health
curl http://<URL>/health

# Check version
curl http://<URL>/info | jq .version
```

## Registry

Images are pushed to: `harbor.cloudnative.biz/tmp/<image>:<tag>`

This is a temporary registry for test builds.

## Rollback

```bash
# Rollback helm release
helm rollback bjorn2scan --kube-context <CONTEXT> --namespace <NAMESPACE>

# Or re-deploy with default values
helm upgrade bjorn2scan ./helm/bjorn2scan \
  --kube-context <CONTEXT> \
  --namespace <NAMESPACE> \
  --reset-values
```

## Troubleshooting

### Image Pull Errors (wrong architecture)

If pods fail with `exec format error` or crash immediately:
1. Check the image architecture: `docker manifest inspect harbor.cloudnative.biz/tmp/bjorn2scan-scan-server:<TAG>`
2. Verify it matches the cluster: `kubectl --context <CONTEXT> get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}'`
3. Rebuild with correct `--platform` flag

### ImagePullBackOff

1. Check image exists: `docker manifest inspect harbor.cloudnative.biz/tmp/bjorn2scan-scan-server:<TAG>`
2. Check cluster can access registry
3. Check image pull secrets if needed

### Setting up buildx (if not available)

```bash
# Create a builder that supports multi-platform
docker buildx create --name multiarch --driver docker-container --use
docker buildx inspect --bootstrap
```
