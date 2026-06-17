package metrics

import (
	"net/http"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentMetrics)

// NewMetricsHandler returns an HTTP handler for the /metrics endpoint.
//
// On each GET request it:
//  1. Queries the staleness store for recently-disappeared metrics (fast indexed read).
//  2. Streams all current metrics to the response while batch-upserting to the staleness DB.
//  3. Emits NaN lines for any stale metrics.
//  4. Asynchronously deletes expired staleness entries.
//
// This replaces Handler, HandlerWithTracker, and HandlerWithNodes.
func NewMetricsHandler(
	info InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	config UnifiedConfig,
	staleness *StalenessStore,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cycleStart := time.Now()

		// Query stale entries before streaming — fast, returns only recently-disappeared metrics.
		staleRows, err := staleness.QueryStale(cycleStart)
		if err != nil {
			log.Error("failed to query stale metrics", "error", err)
			// Continue without NaN lines rather than returning an error response.
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		batch, err := StreamMetrics(w, info, deploymentUUID, provider, config, staleRows, cycleStart)
		if err != nil {
			log.Error("error streaming metrics", "error", err)
		}
		log.Info("metrics stream complete", "duration_ms", time.Since(cycleStart).Milliseconds())

		// Apply staleness diff and delete expired entries after the HTTP response is flushed,
		// so slow PVC writes don't block the client.
		go func() {
			if err := staleness.ApplyDiff(batch, cycleStart); err != nil {
				log.Warn("failed to apply staleness diff", "error", err)
			}
			staleness.DeleteExpired(cycleStart)
		}()
	}
}

// RegisterMetricsHandler registers the /metrics endpoint using the new unified handler.
func RegisterMetricsHandler(
	mux *http.ServeMux,
	info InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	config UnifiedConfig,
	staleness *StalenessStore,
) {
	mux.HandleFunc("/metrics", NewMetricsHandler(info, deploymentUUID, provider, config, staleness))
	log.Info("metrics handler registered at /metrics")
}
