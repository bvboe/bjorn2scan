package k8s

import (
	"context"
	"log/slog"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)


// extractNodeInfo extracts node information from a Kubernetes node object
func extractNodeInfo(node *corev1.Node) nodes.Node {
	n := nodes.Node{
		Name: node.Name,
	}

	// Extract hostname from labels or node info
	if hostname, ok := node.Labels["kubernetes.io/hostname"]; ok {
		n.Hostname = hostname
	}

	// Extract OS information from node status
	if node.Status.NodeInfo.OSImage != "" {
		n.OSRelease = node.Status.NodeInfo.OSImage
	}

	// Extract kernel version
	if node.Status.NodeInfo.KernelVersion != "" {
		n.KernelVersion = node.Status.NodeInfo.KernelVersion
	}

	// Extract architecture
	if node.Status.NodeInfo.Architecture != "" {
		n.Architecture = node.Status.NodeInfo.Architecture
	}

	// Extract container runtime
	if node.Status.NodeInfo.ContainerRuntimeVersion != "" {
		n.ContainerRuntime = node.Status.NodeInfo.ContainerRuntimeVersion
	}

	// Extract kubelet version
	if node.Status.NodeInfo.KubeletVersion != "" {
		n.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	}

	return n
}

// isNodeReady checks if a node is in Ready condition
func isNodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

// WatchNodes watches for node changes using a SharedIndexInformer and updates the node manager.
// This implementation provides:
// - Automatic watch resumption with resourceVersion tracking (no missed events on reconnect)
// - Periodic resync to ensure eventual consistency (every 5 minutes)
// - Built-in exponential backoff on errors
// - Local cache to reduce API server load
// - Proper deletion handling even if watch connection drops
func WatchNodes(ctx context.Context, clientset kubernetes.Interface, manager *nodes.Manager) {
	// Create informer factory with 5-minute resync period
	// Resync ensures we eventually catch up even if watch events are missed
	resyncPeriod := 5 * time.Minute
	factory := informers.NewSharedInformerFactory(clientset, resyncPeriod)

	// Get the node informer
	nodeInformer := factory.Core().V1().Nodes().Informer()

	// Add event handlers
	log := log
	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				log.Warn("unexpected object type in node add", "type", slog.Any("type", obj))
				return
			}
			handleNodeAddOrUpdate(node, manager)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node, ok := newObj.(*corev1.Node)
			if !ok {
				log.Warn("unexpected object type in node update", "type", slog.Any("type", newObj))
				return
			}
			handleNodeAddOrUpdate(node, manager)
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				// Handle tombstone (object deleted from cache but we got notification late)
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					log.Warn("unexpected object type in node delete", "type", slog.Any("type", obj))
					return
				}
				node, ok = tombstone.Obj.(*corev1.Node)
				if !ok {
					log.Warn("tombstone contained unexpected object", "type", slog.Any("type", tombstone.Obj))
					return
				}
			}
			handleNodeDelete(node, manager)
		},
	})
	if err != nil {
		log.Error("failed to add event handler", slog.Any("error", err))
		return
	}

	log.Info("starting node informer")

	// Start the informer (runs in background goroutine)
	go factory.Start(ctx.Done())

	// Wait for cache to sync before considering the informer ready
	log.Info("waiting for node informer cache to sync")
	if !cache.WaitForCacheSync(ctx.Done(), nodeInformer.HasSynced) {
		log.Error("failed to sync node informer cache")
		return
	}

	log.Info("node informer cache synced and ready")

	// Run catch-up now that all nodes are in the manager. This handles nodes that
	// arrived via AddNode after SetScanQueue ran its initial catch-up (timing race),
	// as well as nodes reset to pending by ResetInterruptedScans at startup.
	manager.CatchUpScans()

	// Periodically rescue nodes stuck in an idle non-terminal state (e.g. pending
	// with no scan enqueued). Uses RescueStuckNodes rather than CatchUpScans so
	// nodes currently being scanned (generating_sbom, scanning_vulnerabilities)
	// are not double-enqueued. Aligned with the informer resync period.
	go func() {
		ticker := time.NewTicker(resyncPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				manager.RescueStuckNodes()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	log.Info("node watcher shutting down")
}

// handleNodeAddOrUpdate processes node additions and updates
func handleNodeAddOrUpdate(node *corev1.Node, manager *nodes.Manager) {
	// Only process ready nodes
	if isNodeReady(node) {
		nodeInfo := extractNodeInfo(node)
		manager.AddNode(nodeInfo)
	} else {
		// If node is not ready, we might want to track it differently
		// For now, just log it
		log.Debug("skipping non-ready node", "node", node.Name)
	}
}

// handleNodeDelete processes node deletions
func handleNodeDelete(node *corev1.Node, manager *nodes.Manager) {
	manager.RemoveNode(node.Name)
	log.Debug("removed node", "node", node.Name)
}

// SyncInitialNodes performs an initial sync of all existing nodes.
// Note: With the informer-based WatchNodes implementation, this function is less critical
// since the informer automatically performs an initial list and sync (via cache.WaitForCacheSync).
// This function is kept for explicit synchronization use cases or testing.
func SyncInitialNodes(ctx context.Context, clientset kubernetes.Interface, manager *nodes.Manager) error {
	log := log
	log.Info("performing initial node sync")

	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	var allNodes []nodes.Node
	for _, node := range nodeList.Items {
		// Only track ready nodes
		if isNodeReady(&node) {
			nodeInfo := extractNodeInfo(&node)
			allNodes = append(allNodes, nodeInfo)
		}
	}

	manager.SetNodes(allNodes)
	log.Info("initial node sync complete", "nodes", manager.GetNodeCount())

	return nil
}
