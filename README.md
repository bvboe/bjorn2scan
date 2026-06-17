# Bjørn2Scan v2
<img src="https://github.com/user-attachments/assets/3ec4d350-1cf6-4f2c-a4c6-f19251d70267" width="400" alt="bjorn2scan">

Kubernetes-native vulnerability scanner. It continuously scans the images and hosts running in your cluster with [Grype](https://github.com/anchore/grype) and [Syft](https://github.com/anchore/syft), then surfaces the results in a built-in web dashboard and as Prometheus / OpenTelemetry metrics.

- **Cluster scanning** — every running container image, deduplicated and risk-scored
- **Host & node scanning** — Linux hosts inside or outside Kubernetes
- **Web dashboard** — images, containers, and nodes, plus deployment-wide CVE listings
- **Metrics** — Prometheus endpoint and OpenTelemetry export for Grafana
- **Auto-update** — signed, self-updating deployments and agents

## Quick start (Kubernetes)

You need a Kubernetes cluster (kind, minikube, k3s, MicroK8s, or production), Helm 3, and kubectl.

```bash
# 1. Install bjorn2scan from the signed OCI chart
helm install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan --create-namespace \
  --set clusterName="My Cluster" \
  --wait

# 2. Open the dashboard
kubectl port-forward -n bjorn2scan svc/bjorn2scan 8080:80
```

Then visit **http://localhost:8080**. Scanning starts automatically — results appear within a few minutes as the vulnerability database downloads and pods are scanned.

> K3s, MicroK8s, and standard Kubernetes are auto-detected (containerd socket location) — no extra configuration needed.

## Scan Linux hosts (agent)

To scan a Linux host outside Kubernetes, install the standalone agent:

```bash
curl -sSfL https://github.com/bvboe/b2s-go/releases/latest/download/install.sh | sudo sh
```

This installs a systemd service that scans the host and reports results (`curl http://localhost:9999/health` to check it). See [bjorn2scan-agent/README.md](bjorn2scan-agent/README.md).

## Metrics & dashboards

Bjørn2Scan exposes vulnerability metrics for Prometheus and can export them over OpenTelemetry — point Grafana at them for trends and multi-cluster views. Ready-made Grafana dashboards live in [`docs/`](docs/); details in [docs/PROMETHEUS_METRICS.md](docs/PROMETHEUS_METRICS.md).

## Auto-update

Auto-update is **enabled by default** — the in-cluster update controller and the host agent both keep themselves current, cosign-verified and with health-checked rollback.

To disable it in Kubernetes:

```bash
helm upgrade --install bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan --create-namespace \
  --set updateController.enabled=false
```

For the host agent, set `auto_update_enabled=false` in `agent.conf`. Configuration, version policies, and operational runbooks: [docs/AUTO_UPDATE.md](docs/AUTO_UPDATE.md) and [docs/RUNBOOKS.md](docs/RUNBOOKS.md).

## Configuration

Override any chart value with `--set` or a values file:

```bash
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan \
  --namespace bjorn2scan -f my-values.yaml
```

All options are documented in [`helm/bjorn2scan/values.yaml`](helm/bjorn2scan/values.yaml).

## Upgrade & uninstall

```bash
# Upgrade to the latest chart
helm upgrade bjorn2scan oci://ghcr.io/bvboe/b2s-go/bjorn2scan -n bjorn2scan

# Uninstall
helm uninstall bjorn2scan -n bjorn2scan
kubectl delete namespace bjorn2scan
```

## Verifying releases

Container images and Helm charts are signed with [cosign](https://github.com/sigstore/cosign), and every release is gated on a Grype scan:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/bvboe/b2s-go/*" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  ghcr.io/bvboe/b2s-go/bjorn2scan:<version>
```

## Development

```bash
make build-all          # build every module
make test-all           # run all tests
make helm-kind-deploy   # build images and deploy to a local kind cluster
```

Architecture, module layout, and contributor setup are in [DEVELOPMENT.md](DEVELOPMENT.md).

## Documentation & support

- [DEVELOPMENT.md](DEVELOPMENT.md) — architecture and development guide
- [docs/](docs/) — auto-update, runbooks, metrics, scheduled jobs, CI/CD validation
- [GitHub Issues](https://github.com/bvboe/b2s-go/issues) — bugs and feature requests

## License

Bjørn2Scan is released under the [Apache License 2.0](LICENSE).
