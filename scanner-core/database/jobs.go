package database

import (
	"database/sql"
	"fmt"
	"time"
)

// JobExecution represents a single execution of a scheduled job
type JobExecution struct {
	ID           int64      `json:"id"`
	JobName      string     `json:"job_name"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Status       string     `json:"status"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	DurationMs   *int64     `json:"duration_ms,omitempty"`
}

// RecordJobStart records the start of a job execution and returns the execution ID
func (db *DB) RecordJobStart(jobName string) (int64, error) {
	done := db.beginWrite("record_job_start")
	defer done()
	result, err := db.conn.Exec(`
		INSERT INTO job_executions (job_name, started_at, status)
		VALUES (?, ?, 'running')
	`, jobName, time.Now().UTC())
	if err != nil {
		exitOnCorruption(err)
		return 0, fmt.Errorf("failed to record job start: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get job execution id: %w", err)
	}

	return id, nil
}

// RecordJobSuccess records the successful completion of a job execution
func (db *DB) RecordJobSuccess(executionID int64) error {
	done := db.beginWrite("record_job_success")
	defer done()
	completedAt := time.Now().UTC()

	_, err := db.conn.Exec(`
		UPDATE job_executions
		SET completed_at = ?,
			status = 'completed',
			duration_ms = (julianday(?) - julianday(started_at)) * 86400000
		WHERE id = ?
	`, completedAt, completedAt, executionID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to record job success: %w", err)
	}

	return nil
}

// RecordJobFailure records the failure of a job execution
func (db *DB) RecordJobFailure(executionID int64, errorMsg string) error {
	done := db.beginWrite("record_job_failure")
	defer done()
	completedAt := time.Now().UTC()

	_, err := db.conn.Exec(`
		UPDATE job_executions
		SET completed_at = ?,
			status = 'failed',
			error_message = ?,
			duration_ms = (julianday(?) - julianday(started_at)) * 86400000
		WHERE id = ?
	`, completedAt, errorMsg, completedAt, executionID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to record job failure: %w", err)
	}

	return nil
}

// GetJobExecutions returns recent job executions, optionally filtered by job name
func (db *DB) GetJobExecutions(jobName string, limit int) ([]JobExecution, error) {
	if limit <= 0 {
		limit = 100
	}

	var rows *sql.Rows
	var err error

	if jobName != "" {
		rows, err = db.conn.Query(`
			SELECT id, job_name, started_at, completed_at, status, error_message, duration_ms
			FROM job_executions
			WHERE job_name = ?
			ORDER BY started_at DESC
			LIMIT ?
		`, jobName, limit)
	} else {
		rows, err = db.conn.Query(`
			SELECT id, job_name, started_at, completed_at, status, error_message, duration_ms
			FROM job_executions
			ORDER BY started_at DESC
			LIMIT ?
		`, limit)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query job executions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var executions []JobExecution
	for rows.Next() {
		var exec JobExecution
		var completedAt sql.NullTime
		var errorMsg sql.NullString
		var durationMs sql.NullInt64

		if err := rows.Scan(&exec.ID, &exec.JobName, &exec.StartedAt, &completedAt, &exec.Status, &errorMsg, &durationMs); err != nil {
			return nil, fmt.Errorf("failed to scan job execution: %w", err)
		}

		if completedAt.Valid {
			exec.CompletedAt = &completedAt.Time
		}
		if errorMsg.Valid {
			exec.ErrorMessage = &errorMsg.String
		}
		if durationMs.Valid {
			exec.DurationMs = &durationMs.Int64
		}

		executions = append(executions, exec)
	}

	return executions, rows.Err()
}

// GetLastJobExecution returns the most recent execution for a specific job
func (db *DB) GetLastJobExecution(jobName string) (*JobExecution, error) {
	row := db.conn.QueryRow(`
		SELECT id, job_name, started_at, completed_at, status, error_message, duration_ms
		FROM job_executions
		WHERE job_name = ?
		ORDER BY started_at DESC
		LIMIT 1
	`, jobName)

	var exec JobExecution
	var completedAt sql.NullTime
	var errorMsg sql.NullString
	var durationMs sql.NullInt64

	if err := row.Scan(&exec.ID, &exec.JobName, &exec.StartedAt, &completedAt, &exec.Status, &errorMsg, &durationMs); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get last job execution: %w", err)
	}

	if completedAt.Valid {
		exec.CompletedAt = &completedAt.Time
	}
	if errorMsg.Valid {
		exec.ErrorMessage = &errorMsg.String
	}
	if durationMs.Valid {
		exec.DurationMs = &durationMs.Int64
	}

	return &exec, nil
}

// CleanupOldJobExecutions removes job executions older than the specified number of days
func (db *DB) CleanupOldJobExecutions(daysToKeep int) (int64, error) {
	done := db.beginWrite("cleanup_old_jobs")
	defer done()
	result, err := db.conn.Exec(`
		DELETE FROM job_executions
		WHERE started_at < datetime('now', '-' || ? || ' days')
	`, daysToKeep)
	if err != nil {
		exitOnCorruption(err)
		return 0, fmt.Errorf("failed to cleanup old job executions: %w", err)
	}

	deleted, _ := result.RowsAffected()
	return deleted, nil
}
