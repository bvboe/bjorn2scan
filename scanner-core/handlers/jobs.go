package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/scheduler"
)


// JobExecutionStore defines the interface for job execution database operations
type JobExecutionStore interface {
	GetJobExecutions(jobName string, limit int) ([]database.JobExecution, error)
}

// JobsListHandler handles GET /api/debug/jobs - lists all scheduled jobs
func JobsListHandler(sched *scheduler.Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if sched == nil {
			http.Error(w, "Scheduler not initialized", http.StatusServiceUnavailable)
			return
		}

		jobs := sched.GetJobs()

		// Build response with next run times
		type JobInfo struct {
			Name    string `json:"name"`
			NextRun string `json:"next_run,omitempty"`
		}

		jobInfos := make([]JobInfo, 0, len(jobs))
		for _, name := range jobs {
			info := JobInfo{Name: name}
			if nextRun, err := sched.GetNextRun(name); err == nil {
				info.NextRun = nextRun.Format("2006-01-02T15:04:05Z07:00")
			}
			jobInfos = append(jobInfos, info)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"jobs": jobInfos,
		}); err != nil {
			log.Error("error encoding jobs response", "error", err)
		}
	}
}

// JobsTriggerHandler handles POST /api/debug/jobs/{name}/trigger - triggers a job immediately
func JobsTriggerHandler(sched *scheduler.Scheduler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if sched == nil {
			http.Error(w, "Scheduler not initialized", http.StatusServiceUnavailable)
			return
		}

		// Extract job name from URL path
		// Expected: /api/debug/jobs/{name}/trigger
		path := r.URL.Path
		var jobName string

		// Parse job name from path
		const prefix = "/api/debug/jobs/"
		const suffix = "/trigger"
		if len(path) > len(prefix)+len(suffix) {
			jobName = path[len(prefix) : len(path)-len(suffix)]
		}

		if jobName == "" {
			http.Error(w, "Job name required", http.StatusBadRequest)
			return
		}

		log.Info("triggering job", "job_name", jobName)

		if err := sched.RunJobNow(jobName); err != nil {
			log.Error("failed to trigger job", "job_name", jobName, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "triggered",
			"job":     jobName,
			"message": "Job has been queued for immediate execution",
		}); err != nil {
			log.Error("error encoding trigger response", "error", err)
		}
	}
}

// JobExecutionsHandler handles GET /api/debug/jobs/history - returns job execution history
// Query params:
//   - job: filter by job name (optional)
//   - limit: max number of results (default 100)
func JobExecutionsHandler(db JobExecutionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if db == nil {
			http.Error(w, "Database not initialized", http.StatusServiceUnavailable)
			return
		}

		// Parse query parameters
		jobName := r.URL.Query().Get("job")
		limit := 100
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				limit = l
			}
		}

		executions, err := db.GetJobExecutions(jobName, limit)
		if err != nil {
			log.Error("failed to get job executions", "error", err)
			http.Error(w, "Failed to get job executions", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if executions == nil {
			executions = []database.JobExecution{}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"executions": executions,
			"count":      len(executions),
		}); err != nil {
			log.Error("error encoding executions response", "error", err)
		}
	}
}

// RegisterJobsHandlers registers the jobs debug endpoints
func RegisterJobsHandlers(mux *http.ServeMux, sched *scheduler.Scheduler) {
	mux.HandleFunc("/api/debug/jobs", JobsListHandler(sched))
	mux.HandleFunc("/api/debug/jobs/", JobsTriggerHandler(sched)) // Matches /api/debug/jobs/{name}/trigger
	log.Info("jobs debug handlers registered", "path", "/api/debug/jobs")
}

// RegisterJobsHandlersWithDB registers all jobs debug endpoints including execution history
func RegisterJobsHandlersWithDB(mux *http.ServeMux, sched *scheduler.Scheduler, db JobExecutionStore) {
	mux.HandleFunc("/api/debug/jobs", JobsListHandler(sched))
	mux.HandleFunc("/api/debug/jobs/history", JobExecutionsHandler(db))
	mux.HandleFunc("/api/debug/jobs/", JobsTriggerHandler(sched)) // Matches /api/debug/jobs/{name}/trigger
	log.Info("jobs debug handlers registered", "path", "/api/debug/jobs", "with_history", true)
}
