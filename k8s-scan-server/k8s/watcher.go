package k8s

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/logging"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var log = logging.For(logging.ComponentK8s)

// extractImageReference extracts the image reference from a container image string
// This preserves the original reference exactly as specified by the user
// Example: "nginx:1.21" -> "nginx:1.21"
// Example: "nginx@sha256:abc123" -> "nginx@sha256:abc123" (digest reference preserved)
// Example: "nginx" -> "nginx" (preserved as-is, no normalization to :latest)
func extractImageReference(imageName string) string {
	// Return the image name exactly as specified - preserve user intent
	return imageName
}

// extractDigestFromImageID extracts just the digest from a Kubernetes ImageID
// Example: "docker.io/library/nginx@sha256:abc123..." -> "sha256:abc123..."
// Example: "docker://sha256:abc123..." -> "sha256:abc123..."
// Example: "containerd://sha256:abc123..." -> "sha256:abc123..."
// Example: "sha256:abc123..." -> "sha256:abc123..."
func extractDigestFromImageID(imageID string) string {
	if imageID == "" {
		return ""
	}

	// Strip runtime prefix (docker://, containerd://, etc.) if present
	if idx := strings.Index(imageID, "://"); idx != -1 {
		imageID = imageID[idx+3:]
	}

	// ImageID from Kubernetes can be in format:
	// - "docker.io/library/nginx@sha256:abc123..."
	// - "sha256:abc123..."
	parts := strings.Split(imageID, "@")
	if len(parts) > 1 {
		return parts[1] // Return the digest after @
	}
	// If no @ symbol, check if it's already a digest
	if strings.HasPrefix(imageID, "sha256:") {
		return imageID
	}
	// Otherwise, return empty - this means we don't have a proper digest
	return ""
}

// extractContainers extracts all containers from a pod
func extractContainers(pod *corev1.Pod) []containers.Container {
	var result []containers.Container

	// Get node name from pod spec
	nodeName := pod.Spec.NodeName

	// Process all containers (init, regular, and ephemeral)
	allContainers := append([]corev1.Container{}, pod.Spec.Containers...)
	allContainers = append(allContainers, pod.Spec.InitContainers...)

	// Get container statuses to find imageIDs and runtimes
	type containerStatus struct {
		imageID string
		runtime string
	}
	statusMap := make(map[string]containerStatus)

	// Extract runtime from containerID (e.g., "docker://abc123" or "containerd://abc123")
	extractRuntime := func(containerID string) string {
		if strings.HasPrefix(containerID, "docker://") {
			return "docker"
		} else if strings.HasPrefix(containerID, "containerd://") {
			return "containerd"
		} else if strings.HasPrefix(containerID, "cri-o://") {
			return "cri-o"
		}
		return "unknown"
	}

	for _, status := range pod.Status.ContainerStatuses {
		statusMap[status.Name] = containerStatus{
			imageID: status.ImageID,
			runtime: extractRuntime(status.ContainerID),
		}
	}
	for _, status := range pod.Status.InitContainerStatuses {
		statusMap[status.Name] = containerStatus{
			imageID: status.ImageID,
			runtime: extractRuntime(status.ContainerID),
		}
	}

	for _, container := range allContainers {
		reference := extractImageReference(container.Image)
		status := statusMap[container.Name]
		// Extract just the digest part (e.g., "sha256:abc123...")
		digest := extractDigestFromImageID(status.imageID)

		// Validate that we have complete data before including this container
		if digest == "" {
			// Skip containers without digest - they're not fully initialized yet
			// The watcher will pick them up again when status becomes available
			log.Debug("skipping container without digest",
				"namespace", pod.Namespace, "pod", pod.Name, "container", container.Name, "image", container.Image)
			continue
		}

		if reference == "" {
			log.Warn("container has empty reference",
				"namespace", pod.Namespace, "pod", pod.Name, "container", container.Name)
			continue
		}

		c := containers.Container{
			ID: containers.ContainerID{
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Name:      container.Name,
			},
			Image: containers.ImageID{
				Reference: reference,
				Digest:    digest,
			},
			NodeName:         nodeName,
			ContainerRuntime: status.runtime,
		}
		result = append(result, c)
	}

	return result
}

// WatchPods watches for pod changes using a SharedIndexInformer and updates the container manager.
// This implementation provides:
// - Automatic watch resumption with resourceVersion tracking (no missed events on reconnect)
// - Periodic resync to ensure eventual consistency (every 5 minutes)
// - Built-in exponential backoff on errors
// - Local cache to reduce API server load
// - Proper deletion handling even if watch connection drops
func WatchPods(ctx context.Context, clientset kubernetes.Interface, manager *containers.Manager) {
	// Create informer factory with 5-minute resync period
	// Resync ensures we eventually catch up even if watch events are missed
	resyncPeriod := 5 * time.Minute
	factory := informers.NewSharedInformerFactory(clientset, resyncPeriod)

	// Get the pod informer
	podInformer := factory.Core().V1().Pods().Informer()

	// Add event handlers
	log := log
	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Warn("unexpected object type in pod add", "type", slog.Any("type", obj))
				return
			}
			handlePodAddOrUpdate(pod, manager)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				log.Warn("unexpected object type in pod update", "type", slog.Any("type", newObj))
				return
			}
			handlePodAddOrUpdate(pod, manager)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				// Handle tombstone (object deleted from cache but we got notification late)
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Warn("unexpected object type in pod delete", "type", slog.Any("type", obj))
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					log.Warn("tombstone contained unexpected object", "type", slog.Any("type", tombstone.Obj))
					return
				}
			}
			handlePodDelete(pod, manager)
		},
	})
	if err != nil {
		log.Error("failed to add event handler", slog.Any("error", err))
		return
	}

	log.Info("starting pod informer")

	// Start the informer (runs in background goroutine)
	go factory.Start(ctx.Done())

	// Wait for cache to sync before considering the informer ready
	log.Info("waiting for pod informer cache to sync")
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		log.Error("failed to sync pod informer cache")
		return
	}

	log.Info("pod informer cache synced and ready")

	// Reconcile the DB with the informer's authoritative view of running containers.
	// Removes stale rows from pods that terminated while the scan-server was down
	// (those pods' delete events were missed while the watcher was not running).
	manager.ReconcileDB()

	// Run catch-up now that all containers are in the manager. Handles images whose
	// AddContainer events raced with SetScanQueue, and images reset to pending by
	// ResetInterruptedScans at startup.
	manager.CatchUpScans()

	// Block until context is cancelled
	<-ctx.Done()
	log.Info("pod watcher shutting down")
}

// handlePodAddOrUpdate processes pod additions and updates
func handlePodAddOrUpdate(pod *corev1.Pod, manager *containers.Manager) {
	// Only process running pods
	if pod.Status.Phase == corev1.PodRunning {
		podContainers := extractContainers(pod)
		for _, c := range podContainers {
			manager.AddContainer(c)
		}
	} else {
		// If pod is no longer running, remove its containers
		podContainers := extractContainers(pod)
		for _, c := range podContainers {
			manager.RemoveContainer(c.ID)
		}
	}
}

// handlePodDelete processes pod deletions
func handlePodDelete(pod *corev1.Pod, manager *containers.Manager) {
	// Remove all containers from this deleted pod
	podContainers := extractContainers(pod)
	for _, c := range podContainers {
		manager.RemoveContainer(c.ID)
	}
	log.Debug("removed containers from deleted pod",
		"namespace", pod.Namespace, "pod", pod.Name, "containers", len(podContainers))
}

// SyncInitialPods performs an initial sync of all existing pods.
// Note: With the informer-based WatchPods implementation, this function is less critical
// since the informer automatically performs an initial list and sync (via cache.WaitForCacheSync).
// This function is kept for explicit synchronization use cases or testing.
func SyncInitialPods(ctx context.Context, clientset kubernetes.Interface, manager *containers.Manager) error {
	log := log
	log.Info("performing initial pod sync")

	podList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var allContainers []containers.Container
	for _, pod := range podList.Items {
		// Only track containers from running pods
		if pod.Status.Phase == corev1.PodRunning {
			podContainers := extractContainers(&pod)
			allContainers = append(allContainers, podContainers...)
		}
	}

	manager.SetContainers(allContainers)
	log.Info("initial sync complete", "containers", manager.GetContainerCount())

	return nil
}
