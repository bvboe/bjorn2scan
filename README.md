# Bjørn2Scan - The Kubernetes Vulnerability Scanner
Bjørn2Scan helps track the vulnerabilities in your Kubernetes cluster and help you track it direct in Prometheus/Grafana or wherever you want using OpenTelemetry. Underneath the hood it connects to your container manager (Docker or ContainerD) and scans whatever is running using Syft and Grype, which also means it does not need access to your container registry.

<img src="https://github.com/user-attachments/assets/3ec4d350-1cf6-4f2c-a4c6-f19251d70267" width="400" alt="bjorn2scan">

## Installation
Spin up or connect to your favorite Kubernetes cluster. In this case, https://minikube.sigs.k8s.io/.
```
minikube start
```
Deploy the scanner
```
helm upgrade --install bjorn2scan oci://registry-1.docker.io/bjornvb/bjorn2scan --set clusterName="Minikube Cluster" --wait
```
See https://github.com/bvboe/bjorn2scan/blob/main/bjorn2scan/values.yaml for more configuration options.

Once it's running open up a connection to the web frontend
```
kubectl port-forward service/web-frontend 8080:80
```
Open up your browser at http://localhost:8080 and you're up and running.
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/d94e4cee-33a4-49f0-a762-3a0f9da1fa73">
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/daeb2d6e-daa6-4f55-bc66-fbd1d5aac655">

## Forward data to Prometheus and Grafana for more analysis
This adds Prometheus and Grafana to analyze the data for this Minikube cluster. This deployment approach can modified to monitor multiple Kubernetes clusters.

Install Prometheus and Grafana, configured to retrieve data from the Kubernetes scanner:
```
helm upgrade --install k8s-monitoring prometheus-community/kube-prometheus-stack \
  --set "prometheus.prometheusSpec.maximumStartupDurationSeconds=900" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].job_name=Kubernetes-Vulnerability-Scanner" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].metrics_path=/metrics" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].static_configs[0].targets[0]=vulnerability-coordinator:80" \
  --wait
```

### Explore data in Prometheus
Get access to the Prometheus by running the following command:
```
kubectl port-forward svc/k8s-monitoring-kube-promet-prometheus 9090
```

Open http://localhost:9090 and validate that Prometheus is reading data.
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/d3ce7a2f-7239-4478-87e8-d93823a5c8b5">

Prometheus is importing the following metrics from the Kubernetes scanner:
* kubernetes_vulnerability_results
* kubernetes_vulnerability_sbom
* kubernetes_vulnerability_scanned_containers

This gives information about vulnerabilities found, the software bill of materials for these workloads and an indicator of how many workloads have been scanned.

Also feel free to explore some of the data within Prometheus:
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/5347a71d-9f2e-4ea6-b963-8e09dad67e7a">

### Analyze data in Grafana
Get access to the Grafana by running the following command:
```
kubectl port-forward service/k8s-monitoring-grafana 3000:80
```

Open http://localhost:3000 and log in using default username/password admin/prom-operator:

Open Dashboard page and click New -> Import to import a pre-built Kubernetes vulnerability dashboard:
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/c0ddcb74-92e9-4bfb-9bed-91bd47a48a18">

Open the following link in a separate window, copy into the JSON model window and click Load:
https://raw.githubusercontent.com/bvboe/bjorn2scan/refs/heads/main/grafana-dashboard/container-vulnerability-dashboard.json
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/57aaf0b4-999f-4657-8cde-e0f753c52f9d">

Select the defautl Prometheus datasource for the dashboard and click Import:
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/0213332d-5647-4a96-a301-bad4784710fe">

Start exploring the vulnerability dashboard that was just imported:
<img width="1792" alt="image" src="https://github.com/user-attachments/assets/8ffa3e97-184c-4bab-a4f6-fe7037b34cd8">

### A note about monitoring multiple Kubernetes clusters
It's important that each cluster is given a unique name, which is given when installing the Kubernetes Vulnerability Scanner, as shown below:
```
helm upgrade --install bjorn2scan bjorn2scan --set clusterName="SET NAME OF CLUSTER HERE" --wait
```

Additional clusters can be added to the Prometheus configuration by modifying the helm installation as follows:
```
helm upgrade --install k8s-monitoring prometheus-community/kube-prometheus-stack \
  --set "prometheus.prometheusSpec.maximumStartupDurationSeconds=900" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].job_name=Kubernetes-Vulnerability-Scanner" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].metrics_path=/metrics" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].static_configs[0].targets[0]=vulnerability-coordinator:80" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].static_configs[0].targets[1]=cluster-number-two:80" \
  --set "prometheus.prometheusSpec.additionalScrapeConfigs[0].static_configs[0].targets[2]=cluster-number-three:80" \
  --wait
```

## Uninstallation
Use Helm to see what's installed
```
helm list
```

Ask Helm to delete the monitoring and scanning components:
```
helm delete k8s-monitoring bjorn2scan
```

## Troubleshooting and Testing
The scanner is designed to work with Kubernetes running on Docker and ContainerD, and has been tested on the following Kubernetes distributions:
* Amazon Elastic Kubernetes Service (EKS)
* Google Kubernetes Engine (GKE)
* K3s
* MicroK8s (see note about verifying SSL)
* Kubeadm on ContainerD
* Minikube
* Kind

The scanner is currently not integrated with CRI-O.

The scanner will also require read-only access to the host operating system and leverages a Persistent Volume Claim for caching scan results. The use of a Persistent Volume Claim can be disabled by adding `--set vulnerabilityCoordinator.externalStorage=false` to the helm installation command.

Known issue on MicroK8s: Add `--set kubernetes.verifySSL="false"` to disable Kubernetes SSL verification if the following error appears:
```
urllib3.connectionpool - WARNING - Retrying (Retry(total=2, connect=None, read=None, redirect=None, status=None)) after connection broken by 'SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: CA cert does not include key usage extension (_ssl.c:1028)'))': /api/v1/nodes
```
