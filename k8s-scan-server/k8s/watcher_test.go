package k8s

import (
	"context"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExtractImageReference(t *testing.T) {
	tests := []struct {
		name          string
		imageName     string
		wantReference string
	}{
		{
			name:          "simple image with tag",
			imageName:     "nginx:1.21",
			wantReference: "nginx:1.21",
		},
		{
			name:          "simple image without tag preserved as-is",
			imageName:     "nginx",
			wantReference: "nginx",
		},
		{
			name:          "fully qualified image with tag",
			imageName:     "docker.io/library/nginx:1.21",
			wantReference: "docker.io/library/nginx:1.21",
		},
		{
			name:          "gcr image with tag",
			imageName:     "gcr.io/myproject/myimage:v1.2.3",
			wantReference: "gcr.io/myproject/myimage:v1.2.3",
		},
		{
			name:          "image with tag and digest preserves full reference",
			imageName:     "nginx:1.21@sha256:abc123",
			wantReference: "nginx:1.21@sha256:abc123",
		},
		{
			name:          "image with only digest preserves digest reference",
			imageName:     "nginx@sha256:abc123",
			wantReference: "nginx@sha256:abc123",
		},
		{
			name:          "harbor registry image with digest only preserves full reference",
			imageName:     "harbor.cloudnative.biz/chainguard-mirror/calico-cni@sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
			wantReference: "harbor.cloudnative.biz/chainguard-mirror/calico-cni@sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
		},
		{
			name:          "image with port in registry",
			imageName:     "localhost:5000/myimage:latest",
			wantReference: "localhost:5000/myimage:latest",
		},
		{
			name:          "empty string preserved as-is",
			imageName:     "",
			wantReference: "",
		},
		{
			name:          "image with multiple path components",
			imageName:     "registry.k8s.io/kube-proxy:v1.28.0",
			wantReference: "registry.k8s.io/kube-proxy:v1.28.0",
		},
		{
			name:          "image with sha1 tag",
			imageName:     "myimage:abc123def456",
			wantReference: "myimage:abc123def456",
		},
		{
			name:          "image with port in registry and no tag preserved as-is",
			imageName:     "localhost:5000/myimage",
			wantReference: "localhost:5000/myimage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotReference := extractImageReference(tt.imageName)
			if gotReference != tt.wantReference {
				t.Errorf("extractImageReference() = %v, want %v", gotReference, tt.wantReference)
			}
		})
	}
}

func TestExtractDigestFromImageID(t *testing.T) {
	tests := []struct {
		name       string
		imageID    string
		wantDigest string
	}{
		{
			name:       "full ImageID with repository and digest",
			imageID:    "docker.io/library/nginx@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantDigest: "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:       "ImageID with short repository",
			imageID:    "nginx@sha256:abc123def456",
			wantDigest: "sha256:abc123def456",
		},
		{
			name:       "just digest without repository",
			imageID:    "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantDigest: "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:       "empty string",
			imageID:    "",
			wantDigest: "",
		},
		{
			name:       "ImageID without digest",
			imageID:    "nginx:1.21",
			wantDigest: "",
		},
		{
			name:       "ImageID with registry and digest",
			imageID:    "gcr.io/myproject/myimage@sha256:1234567890abcdef",
			wantDigest: "sha256:1234567890abcdef",
		},
		{
			name:       "ImageID with localhost registry",
			imageID:    "localhost:5000/myimage@sha256:fedcba0987654321",
			wantDigest: "sha256:fedcba0987654321",
		},
		{
			name:       "malformed ImageID with multiple @ symbols takes first digest",
			imageID:    "registry.io/image@sha256:abc@extra",
			wantDigest: "sha256:abc",
		},
		{
			name:       "ImageID with sha512 digest",
			imageID:    "myimage@sha512:abcdef123456",
			wantDigest: "sha512:abcdef123456",
		},
		{
			name:       "just repository without digest",
			imageID:    "docker.io/library/nginx",
			wantDigest: "",
		},
		{
			name:       "ImageID with tag and digest",
			imageID:    "nginx:1.21@sha256:abc123",
			wantDigest: "sha256:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDigest := extractDigestFromImageID(tt.imageID)
			if gotDigest != tt.wantDigest {
				t.Errorf("extractDigestFromImageID() = %v, want %v", gotDigest, tt.wantDigest)
			}
		})
	}
}

// TestExtractImageReferenceAndDigest tests the combination of both functions
// to ensure they work correctly together as used in extractContainerInstances
func TestExtractImageReferenceAndDigest(t *testing.T) {
	tests := []struct {
		name           string
		containerImage string // from pod.spec.containers[].image
		statusImageID  string // from pod.status.containerStatuses[].imageID
		wantReference  string
		wantDigest     string
	}{
		{
			name:           "typical Kubernetes pod status",
			containerImage: "nginx:1.21",
			statusImageID:  "docker.io/library/nginx@sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
			wantReference:  "nginx:1.21",
			wantDigest:     "sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac",
		},
		{
			name:           "image without tag preserved as-is",
			containerImage: "nginx",
			statusImageID:  "docker.io/library/nginx@sha256:abc123",
			wantReference:  "nginx",
			wantDigest:     "sha256:abc123",
		},
		{
			name:           "fully qualified image with private registry",
			containerImage: "gcr.io/myproject/myimage:v1.0.0",
			statusImageID:  "gcr.io/myproject/myimage@sha256:def456",
			wantReference:  "gcr.io/myproject/myimage:v1.0.0",
			wantDigest:     "sha256:def456",
		},
		{
			name:           "pending pod without status",
			containerImage: "nginx:1.21",
			statusImageID:  "",
			wantReference:  "nginx:1.21",
			wantDigest:     "",
		},
		{
			name:           "image specified by digest preserves digest reference",
			containerImage: "nginx@sha256:original123",
			statusImageID:  "docker.io/library/nginx@sha256:actual456",
			wantReference:  "nginx@sha256:original123",
			wantDigest:     "sha256:actual456",
		},
		{
			name:           "harbor calico image pulled by digest preserves full reference",
			containerImage: "harbor.cloudnative.biz/chainguard-mirror/calico-cni@sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
			statusImageID:  "harbor.cloudnative.biz/chainguard-mirror/calico-cni@sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
			wantReference:  "harbor.cloudnative.biz/chainguard-mirror/calico-cni@sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
			wantDigest:     "sha256:6ac36c78896157d10d99a02206f124cb157ec4f57bd95ebb20bb930c0ce25f8d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate what happens in extractContainerInstances
			gotReference := extractImageReference(tt.containerImage)
			gotDigest := extractDigestFromImageID(tt.statusImageID)

			if gotReference != tt.wantReference {
				t.Errorf("reference = %v, want %v", gotReference, tt.wantReference)
			}
			if gotDigest != tt.wantDigest {
				t.Errorf("digest = %v, want %v", gotDigest, tt.wantDigest)
			}
		})
	}
}

// TestWatchPodsInformerIntegration tests the informer-based pod watcher with add/update/delete events
func TestWatchPodsInformerIntegration(t *testing.T) {
	// Create fake clientset
	clientset := fake.NewClientset()

	// Create a manager to track containers
	manager := containers.NewManager()

	// Create a test pod with running status
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.21",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "nginx",
					ImageID:     "docker.io/library/nginx@sha256:abc123",
					ContainerID: "containerd://xyz789",
				},
			},
		},
	}

	// Add the pod to the fake clientset
	_, err := clientset.CoreV1().Pods("default").Create(context.Background(), testPod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create test pod: %v", err)
	}

	// Start the watcher in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go WatchPods(ctx, clientset, manager)

	// Wait for informer to sync
	time.Sleep(500 * time.Millisecond)

	// Verify pod was added to manager
	count := manager.GetContainerCount()
	if count != 1 {
		t.Errorf("Expected 1 container, got %d", count)
	}

	// Verify container details
	c, exists := manager.GetContainer("default", "test-pod", "nginx")
	if !exists {
		t.Fatal("Container not found in manager")
	}

	if c.Image.Reference != "nginx:1.21" {
		t.Errorf("Expected reference 'nginx:1.21', got '%s'", c.Image.Reference)
	}
	if c.Image.Digest != "sha256:abc123" {
		t.Errorf("Expected digest 'sha256:abc123', got '%s'", c.Image.Digest)
	}
	if c.NodeName != "node-1" {
		t.Errorf("Expected node 'node-1', got '%s'", c.NodeName)
	}
	if c.ContainerRuntime != "containerd" {
		t.Errorf("Expected runtime 'containerd', got '%s'", c.ContainerRuntime)
	}
}

// TestWatchPodsInformerDeletion tests that pod deletions are properly handled
func TestWatchPodsInformerDeletion(t *testing.T) {
	// Create fake clientset with a test pod
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.21",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "nginx",
					ImageID:     "docker.io/library/nginx@sha256:abc123",
					ContainerID: "containerd://xyz789",
				},
			},
		},
	}

	clientset := fake.NewClientset(testPod)
	manager := containers.NewManager()

	// Start the watcher
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go WatchPods(ctx, clientset, manager)

	// Wait for informer to sync and add pod
	time.Sleep(500 * time.Millisecond)

	// Verify pod was added
	if manager.GetContainerCount() != 1 {
		t.Fatalf("Expected 1 container after add, got %d", manager.GetContainerCount())
	}

	// Delete the pod
	err := clientset.CoreV1().Pods("default").Delete(context.Background(), "test-pod", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("Failed to delete test pod: %v", err)
	}

	// Wait for informer to process deletion
	time.Sleep(500 * time.Millisecond)

	// Verify pod was removed from manager
	count := manager.GetContainerCount()
	if count != 0 {
		t.Errorf("Expected 0 containers after deletion, got %d", count)
	}

	// Verify container no longer exists
	_, exists := manager.GetContainer("default", "test-pod", "nginx")
	if exists {
		t.Error("Container still exists in manager after pod deletion")
	}
}

// TestWatchPodsInformerUpdate tests that pod status changes (Running -> NotRunning) remove containers
func TestWatchPodsInformerUpdate(t *testing.T) {
	// Create fake clientset with a running test pod
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.21",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "nginx",
					ImageID:     "docker.io/library/nginx@sha256:abc123",
					ContainerID: "containerd://xyz789",
				},
			},
		},
	}

	clientset := fake.NewClientset(testPod)
	manager := containers.NewManager()

	// Start the watcher
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go WatchPods(ctx, clientset, manager)

	// Wait for informer to sync and add pod
	time.Sleep(500 * time.Millisecond)

	// Verify pod was added
	if manager.GetContainerCount() != 1 {
		t.Fatalf("Expected 1 container after add, got %d", manager.GetContainerCount())
	}

	// Update pod status to Failed (not running)
	testPod.Status.Phase = corev1.PodFailed
	_, err := clientset.CoreV1().Pods("default").Update(context.Background(), testPod, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to update test pod: %v", err)
	}

	// Wait for informer to process update
	time.Sleep(500 * time.Millisecond)

	// Verify pod was removed from manager (since it's no longer running)
	count := manager.GetContainerCount()
	if count != 0 {
		t.Errorf("Expected 0 containers after pod failed, got %d", count)
	}

	// Verify container no longer exists
	_, exists := manager.GetContainer("default", "test-pod", "nginx")
	if exists {
		t.Error("Container still exists in manager after pod failed")
	}
}

// TestWatchPodsInformerMultiplePods tests handling multiple pods simultaneously
func TestWatchPodsInformerMultiplePods(t *testing.T) {
	// Create fake clientset with multiple running pods
	clientset := fake.NewClientset()
	manager := containers.NewManager()

	// Start the watcher
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go WatchPods(ctx, clientset, manager)

	// Wait for informer to start
	time.Sleep(300 * time.Millisecond)

	// Create multiple pods
	for i := 1; i <= 3; i++ {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-" + string(rune('a'+i-1)),
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				NodeName: "node-1",
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.21",
					},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name:        "nginx",
						ImageID:     "docker.io/library/nginx@sha256:abc123",
						ContainerID: "containerd://xyz" + string(rune('0'+i)),
					},
				},
			},
		}

		_, err := clientset.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create test pod %d: %v", i, err)
		}
	}

	// Wait for informer to process all pods
	time.Sleep(500 * time.Millisecond)

	// Verify all pods were added
	count := manager.GetContainerCount()
	if count != 3 {
		t.Errorf("Expected 3 containers, got %d", count)
	}
}
