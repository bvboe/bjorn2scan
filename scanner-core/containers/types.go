package containers

// ContainerID identifies a specific container within a pod
type ContainerID struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Name      string `json:"name"` // Container name within the pod
}

// ImageID identifies a container image
type ImageID struct {
	Reference string `json:"reference"` // Original image reference (e.g., "nginx:1.21" or "nginx@sha256:abc...")
	Digest    string `json:"digest"`    // SHA256 digest (e.g., sha256:abc123...)
}

// Container represents a running container in the cluster
type Container struct {
	ID               ContainerID `json:"id"`
	Image            ImageID     `json:"image"`
	NodeName         string      `json:"node_name"`         // K8s node name (empty for agent)
	ContainerRuntime string      `json:"container_runtime"` // "docker" or "containerd"
}

// ContainerCollection represents a collection of containers
type ContainerCollection struct {
	Containers []Container `json:"containers"`
}
