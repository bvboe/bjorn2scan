# bjorn2scan Helm Chart

A Helm chart for deploying bjorn2scan v2 - Kubernetes container and workload scanner with vulnerability detection.

## Features

- **Container Image Scanning**: Automatic SBOM generation and vulnerability scanning for all running containers
- **Multi-Distribution Support**: Works with standard Kubernetes, K3s, MicroK8s, and custom distributions
- **Auto-Update**: Optional automatic updates for both the Helm chart and agent binary
- **Web UI**: Built-in dashboard for viewing scan results and vulnerabilities

## Installation

### Standard Kubernetes

```bash
helm install bjorn2scan ./helm/bjorn2scan
```

### K3s

```bash
helm install bjorn2scan ./helm/bjorn2scan
```

The chart automatically detects K3s and uses `/run/k3s/containerd/containerd.sock`.

### MicroK8s

```bash
helm install bjorn2scan ./helm/bjorn2scan
```

The chart automatically detects MicroK8s and uses `/var/snap/microk8s/common/run/containerd.sock`.

### Custom Distributions

If your distribution uses a non-standard containerd socket path:

```bash
helm install bjorn2scan ./helm/bjorn2scan \
  --set podScanner.config.containerdSocket="/custom/path/containerd.sock"
```

## Configuration

### Container Runtime Socket

The pod-scanner component automatically detects the containerd socket location by:

1. Checking the `CONTAINERD_SOCKET` environment variable (if set)
2. Testing each known socket location in order:
   - `/run/containerd/containerd.sock` (Standard Kubernetes)
   - `/run/k3s/containerd/containerd.sock` (K3s)
   - `/var/snap/microk8s/common/run/containerd.sock` (MicroK8s)
   - `/run/dockershim.sock` (Legacy)
3. **Verifying the connection works** by calling the containerd API
4. Using the first socket that responds successfully

You can override the auto-detection in `values.yaml`:

```yaml
podScanner:
  config:
    # Auto-detect (recommended)
    containerdSocket: ""

    # Or force a specific path
    # containerdSocket: "/run/k3s/containerd/containerd.sock"
```

### Verifying Socket Detection

Check the pod-scanner logs to see which socket was detected:

```bash
kubectl logs -l app.kubernetes.io/component=pod-scanner | grep "Detected containerd socket"
```

Expected output:
- Standard K8s: `Detected containerd socket: /run/containerd/containerd.sock`
- K3s: `Detected containerd socket: /run/k3s/containerd/containerd.sock`
- MicroK8s: `Detected containerd socket: /var/snap/microk8s/common/run/containerd.sock`

## Components

### scan-server (Deployment)

Central API server that:
- Aggregates scan results from all nodes
- Provides REST API and Web UI
- Stores data in SQLite database

### pod-scanner (DaemonSet)

Runs on every node to:
- Monitor containers via the container runtime API
- Generate SBOMs using Syft
- Scan for vulnerabilities using Grype
- Report results to scan-server

**Requirements:**
- Privileged access (needs container runtime socket)
- Access to containerd data directory for layer mounting

### update-controller (CronJob)

Optional component that:
- Automatically checks for new Helm chart versions
- Updates the deployment with configurable constraints
- Supports version pinning and constraints

## Troubleshooting

### Pod-scanner fails to start on K3s/MicroK8s

**Symptoms:**
```
Failed to create ContainerD client with socket /run/containerd/containerd.sock: ...
```

**Solution:**

The auto-detection should handle this, but if it fails:

1. Check which socket your distribution uses:
   ```bash
   # On the node
   find /run /var -name "containerd.sock" 2>/dev/null
   ```

2. Override in values.yaml:
   ```yaml
   podScanner:
     config:
       containerdSocket: "/path/to/your/containerd.sock"
   ```

3. Verify the socket is accessible:
   ```bash
   kubectl exec -it <pod-scanner-pod> -- ls -la /run/k3s/containerd/containerd.sock
   ```

### No images detected

**Symptoms:**
Pod-scanner is running but no images are showing up in the database.

**Check:**

1. Verify socket detection:
   ```bash
   kubectl logs -l app.kubernetes.io/component=pod-scanner | grep "socket"
   ```

2. Check containerd namespace (Kubernetes uses `k8s.io`):
   ```bash
   kubectl exec -it <pod-scanner-pod> -- ctr -a /run/containerd/containerd.sock -n k8s.io images ls
   ```

## Advanced Configuration

### Resource Limits

Pod-scanner spikes CPU/memory during SBOM generation:

```yaml
podScanner:
  resources:
    limits:
      cpu: 2000m      # Peak during scan
      memory: 2Gi
    requests:
      cpu: 100m       # Baseline when idle
      memory: 256Mi
```

### Node Selection

Run pod-scanner only on specific nodes:

```yaml
podScanner:
  nodeSelector:
    workload: scanner

  tolerations:
    - key: dedicated
      operator: Equal
      value: scanner
      effect: NoSchedule
```

### Disable Components

```yaml
# Disable pod-scanner (k8s-scan-server only)
podScanner:
  enabled: false

# Disable auto-updates
updateController:
  enabled: false
```

## Support

- GitHub: https://github.com/bvboe/bjorn2scan
- Issues: https://github.com/bvboe/bjorn2scan/issues
