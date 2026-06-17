package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
)


// DebugSQLHandler handles POST /debug/sql requests to execute SQL queries.
//
// WARNING: This endpoint allows ALL SQL statements including INSERT, UPDATE, DELETE, DROP, etc.
// Only enable in development/testing environments. Do not enable in production.
//
// Request format:
//
//	POST /debug/sql
//	Content-Type: application/json
//	{
//	  "query": "SELECT * FROM images LIMIT 10"
//	}
//
// Response format for SELECT queries:
//
//	{
//	  "columns": ["column1", "column2"],
//	  "rows": [
//	    {"column1": "value1", "column2": "value2"},
//	    {"column1": "value3", "column2": "value4"}
//	  ],
//	  "row_count": 2
//	}
//
// Response format for INSERT/UPDATE/DELETE queries:
//
//	{
//	  "columns": ["rows_affected"],
//	  "rows": [{"rows_affected": 5}],
//	  "row_count": 1,
//	  "rows_affected": 5
//	}
func DebugSQLHandler(db *database.DB, debugConfig *debug.DebugConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if debug mode is enabled
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		// Only accept POST requests
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON body
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Warn("failed to close request body", "error", err)
			}
		}()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error("error reading request body", "error", err)
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var request struct {
			Query string `json:"query"`
		}

		if err := json.Unmarshal(body, &request); err != nil {
			log.Error("error parsing JSON", "error", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if request.Query == "" {
			http.Error(w, "Query is required", http.StatusBadRequest)
			return
		}

		// Validate SQL query
		valid, err := debug.ValidateQuery(request.Query)
		if !valid {
			log.Warn("invalid SQL query rejected", "error", err)
			http.Error(w, fmt.Sprintf("Invalid query: %v", err), http.StatusBadRequest)
			return
		}

		// Execute query
		result, err := db.ExecuteQuery(request.Query)
		if err != nil {
			log.Error("error executing query", "error", err)
			http.Error(w, fmt.Sprintf("Query execution failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Build response with columns array to preserve order
		response := map[string]interface{}{
			"columns":   result.Columns,
			"rows":      result.Rows,
			"row_count": len(result.Rows),
		}

		// Include rows_affected for write queries
		if result.RowsAffected > 0 {
			response["rows_affected"] = result.RowsAffected
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// DebugMetricsHandler handles GET /debug/metrics requests to retrieve performance metrics.
//
// Response format:
//
//	{
//	  "request_count": 123,
//	  "total_duration_ms": 5000,
//	  "queue_depth": 5,
//	  "last_updated": "2025-12-18T00:00:00Z",
//	  "endpoints": {
//	    "/api/images": {
//	      "count": 50,
//	      "total_duration_ms": 2500,
//	      "avg_duration_ms": 50,
//	      "last_access": "2025-12-18T00:00:00Z"
//	    }
//	  }
//	}
func DebugMetricsHandler(debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if debug mode is enabled
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get metrics from debug config
		metrics := debugConfig.GetMetrics()

		// Update queue depth from scan queue
		if scanQueue != nil {
			debugConfig.SetQueueDepth(scanQueue.GetQueueDepth())
			metrics = debugConfig.GetMetrics() // Refresh to get updated queue depth
		}

		// Build response with endpoint details
		endpointDetails := make(map[string]interface{})
		for endpoint, em := range metrics.EndpointMetrics {
			avgDuration := float64(0)
			if em.Count > 0 {
				avgDuration = float64(em.TotalDuration.Milliseconds()) / float64(em.Count)
			}

			endpointDetails[endpoint] = map[string]interface{}{
				"count":             em.Count,
				"total_duration_ms": em.TotalDuration.Milliseconds(),
				"avg_duration_ms":   avgDuration,
				"last_access":       em.LastAccess,
			}
		}

		response := map[string]interface{}{
			"request_count":     metrics.RequestCount,
			"total_duration_ms": metrics.TotalDuration.Milliseconds(),
			"queue_depth":       metrics.QueueDepth,
			"last_updated":      metrics.LastUpdated,
			"endpoints":         endpointDetails,
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// DebugQueueHandler handles GET /api/debug/queue requests to get queue contents.
//
// Response format:
//
//	{
//	  "current_depth": 5,
//	  "peak_depth": 12,
//	  "total_enqueued": 1547,
//	  "total_dropped": 3,
//	  "total_processed": 1539,
//	  "jobs": [
//	    {"type": "image", "image": "nginx:latest", "digest": "sha256:...", "node_name": "worker-1", "force_scan": false},
//	    {"type": "host", "node_name": "worker-1", "force_scan": true, "full_rescan": false}
//	  ]
//	}
func DebugQueueHandler(debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if scanQueue == nil {
			http.Error(w, "Scan queue not available", http.StatusServiceUnavailable)
			return
		}

		contents := scanQueue.GetQueueContents()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(contents); err != nil {
			log.Error("error encoding queue contents", "error", err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// DebugRescanNodeHandler handles POST /api/debug/rescan/node/{name} to manually trigger a node rescan.
//
// Optional request body:
//
//	{"full_rescan": true}
//
// Response: {"status": "queued", "node": "worker-1"}
func DebugRescanNodeHandler(debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if scanQueue == nil {
			http.Error(w, "Scan queue not available", http.StatusServiceUnavailable)
			return
		}

		// Extract node name from URL path: /api/debug/rescan/node/{name}
		nodeName := r.URL.Path[len("/api/debug/rescan/node/"):]
		if nodeName == "" {
			http.Error(w, "Node name required", http.StatusBadRequest)
			return
		}

		// Parse optional body for full_rescan flag
		fullRescan := false
		if r.Body != nil && r.ContentLength > 0 {
			var body struct {
				FullRescan bool `json:"full_rescan"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				fullRescan = body.FullRescan
			}
		}

		// Enqueue the host scan
		if fullRescan {
			scanQueue.EnqueueHostFullRescan(nodeName)
		} else {
			scanQueue.EnqueueHostForceScan(nodeName)
		}

		log.Debug("enqueued manual node rescan", "node_name", nodeName, "full_rescan", fullRescan)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":      "queued",
			"node":        nodeName,
			"full_rescan": fullRescan,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
		}
	}
}

// DebugRescanImageHandler handles POST /api/debug/rescan/image/{digest} to manually trigger an image rescan.
//
// Optional request body:
//
//	{"force_sbom": true}
//
// Response: {"status": "queued", "digest": "sha256:..."}
func DebugRescanImageHandler(debugConfig *debug.DebugConfig, db *database.DB, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if scanQueue == nil {
			http.Error(w, "Scan queue not available", http.StatusServiceUnavailable)
			return
		}

		// Extract digest from URL path: /api/debug/rescan/image/{digest}
		digest := r.URL.Path[len("/api/debug/rescan/image/"):]
		if digest == "" {
			http.Error(w, "Image digest required", http.StatusBadRequest)
			return
		}

		// Parse optional body for force_sbom flag
		forceSBOM := false
		if r.Body != nil && r.ContentLength > 0 {
			var body struct {
				ForceSBOM bool `json:"force_sbom"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				forceSBOM = body.ForceSBOM
			}
		}

		// Look up image info from database to get a reference
		// We need at least a digest to create an ImageID
		imageID := containers.ImageID{
			Digest:    digest,
			Reference: digest, // Use digest as reference if we don't have one
		}

		// Enqueue the image scan
		job := scanning.ScanJob{
			Image:     imageID,
			ForceScan: true, // Always force since this is a manual rescan
		}

		// If force_sbom is set, we need to clear the SBOM status first
		// For now, just use ForceScan which will rescan vulnerabilities
		// A full SBOM regeneration would require additional queue changes
		_ = forceSBOM // Reserved for future enhancement

		scanQueue.Enqueue(job)

		log.Debug("enqueued manual image rescan", "digest", digest)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status": "queued",
			"digest": digest,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
		}
	}
}

// DebugRescanAllNodesHandler handles POST /api/debug/rescan/all-nodes to trigger rescan of all nodes.
//
// Response: {"status": "queued", "count": 5}
func DebugRescanAllNodesHandler(debugConfig *debug.DebugConfig, db *database.DB, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if scanQueue == nil {
			http.Error(w, "Scan queue not available", http.StatusServiceUnavailable)
			return
		}

		// Get all nodes from database
		nodes, err := db.GetAllNodes()
		if err != nil {
			log.Error("error getting nodes for rescan", "error", err)
			http.Error(w, "Failed to get nodes", http.StatusInternalServerError)
			return
		}

		// Enqueue rescan for each node
		for _, node := range nodes {
			scanQueue.EnqueueHostForceScan(node.Name)
		}

		log.Debug("enqueued node rescan batch", "count", len(nodes))

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status": "queued",
			"count":  len(nodes),
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
		}
	}
}

// DebugRescanAllImagesHandler handles POST /api/debug/rescan/all-images to trigger rescan of all images.
//
// Response: {"status": "queued", "count": 50}
func DebugRescanAllImagesHandler(debugConfig *debug.DebugConfig, db *database.DB, scanQueue *scanning.JobQueue) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debugConfig.IsEnabled() {
			http.Error(w, "Debug mode not enabled", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if scanQueue == nil {
			http.Error(w, "Scan queue not available", http.StatusServiceUnavailable)
			return
		}

		// Get all images from database
		imagesRaw, err := db.GetAllImages()
		if err != nil {
			log.Error("error getting images for rescan", "error", err)
			http.Error(w, "Failed to get images", http.StatusInternalServerError)
			return
		}

		images, ok := imagesRaw.([]database.ContainerImage)
		if !ok {
			http.Error(w, "Failed to convert images", http.StatusInternalServerError)
			return
		}

		// Enqueue rescan for each image
		for _, img := range images {
			job := scanning.ScanJob{
				Image: containers.ImageID{
					Digest:    img.Digest,
					Reference: img.Digest,
				},
				ForceScan: true,
			}
			scanQueue.Enqueue(job)
		}

		log.Debug("enqueued image rescan batch", "count", len(images))

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status": "queued",
			"count":  len(images),
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding response", "error", err)
		}
	}
}

// RegisterDebugHandlers registers debug endpoints on the provided mux.
// If debug mode is not enabled, handlers are not registered (zero overhead).
//
// Endpoints:
//   - POST /api/debug/sql - Execute SQL queries (SELECT, INSERT, UPDATE, DELETE, etc.)
//   - GET /api/debug/metrics - Retrieve performance metrics
//   - GET /api/debug/queue - Get current queue contents
//   - POST /api/debug/rescan/node/{name} - Rescan a specific node
//   - POST /api/debug/rescan/image/{digest} - Rescan a specific image
//   - POST /api/debug/rescan/all-nodes - Rescan all nodes
//   - POST /api/debug/rescan/all-images - Rescan all images
func RegisterDebugHandlers(mux *http.ServeMux, db *database.DB, debugConfig *debug.DebugConfig, scanQueue *scanning.JobQueue) {
	if debugConfig == nil || !debugConfig.IsEnabled() {
		// Don't register handlers if debug not enabled
		return
	}

	mux.HandleFunc("/api/debug/sql", DebugSQLHandler(db, debugConfig))
	mux.HandleFunc("/api/debug/metrics", DebugMetricsHandler(debugConfig, scanQueue))
	mux.HandleFunc("/api/debug/queue", DebugQueueHandler(debugConfig, scanQueue))
	mux.HandleFunc("/api/debug/rescan/node/", DebugRescanNodeHandler(debugConfig, scanQueue))
	mux.HandleFunc("/api/debug/rescan/image/", DebugRescanImageHandler(debugConfig, db, scanQueue))
	mux.HandleFunc("/api/debug/rescan/all-nodes", DebugRescanAllNodesHandler(debugConfig, db, scanQueue))
	mux.HandleFunc("/api/debug/rescan/all-images", DebugRescanAllImagesHandler(debugConfig, db, scanQueue))

	log.Info("debug handlers registered", "endpoints", "/api/debug/sql, /api/debug/metrics, /api/debug/queue, /api/debug/rescan/*")
}
