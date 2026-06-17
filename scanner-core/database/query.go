package database

import (
	"fmt"
	"strings"
	"time"
)

// QueryResult represents the result of a SQL query with column order preserved.
type QueryResult struct {
	Columns      []string                 `json:"columns"`
	Rows         []map[string]interface{} `json:"rows"`
	RowsAffected int64                    `json:"rows_affected,omitempty"`
}

// ExecuteQuery executes a SQL query and returns results.
// For SELECT queries, it returns rows with column data.
// For INSERT/UPDATE/DELETE queries, it returns the number of rows affected.
//
// This method is intended for debug/diagnostic purposes only and should only be called
// from the debug SQL handler after proper validation.
//
// WARNING: This method does NOT validate the SQL query. The caller MUST ensure the query
// is safe before calling this method. Use debug.ValidateQuery() to validate queries.
func (db *DB) ExecuteQuery(query string) (*QueryResult, error) {
	// Log the SQL query for tracking
	log.Debug("executing query", "query", query)
	start := time.Now()

	// Determine if this is a read query (SELECT) or a write query (INSERT/UPDATE/DELETE/etc.)
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	isSelect := strings.HasPrefix(trimmed, "SELECT") ||
		strings.HasPrefix(trimmed, "WITH") || // CTEs
		strings.HasPrefix(trimmed, "PRAGMA") ||
		strings.HasPrefix(trimmed, "EXPLAIN")

	if isSelect {
		return db.executeSelectQuery(query, start)
	}
	return db.executeWriteQuery(query, start)
}

// executeSelectQuery handles SELECT queries and returns row data.
func (db *DB) executeSelectQuery(query string, start time.Time) (*QueryResult, error) {
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			// Log but don't fail on close error
			log.Warn("failed to close rows", "error", err)
		}
	}()

	// Get column names (preserves database order)
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Build result set
	var results []map[string]interface{}

	for rows.Next() {
		// Create slice for scanning
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row into value pointers
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Build map for this row
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]

			// Convert []byte to string for better JSON serialization
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}

		results = append(results, row)
	}

	// Check for errors from iteration
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	// Log completion with row count and duration
	duration := time.Since(start)
	log.Debug("query completed", "rows_returned", len(results), "duration", duration)

	return &QueryResult{
		Columns: columns,
		Rows:    results,
	}, nil
}

// executeWriteQuery handles INSERT/UPDATE/DELETE queries and returns rows affected.
func (db *DB) executeWriteQuery(query string, start time.Time) (*QueryResult, error) {
	result, err := db.conn.Exec(query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %w", err)
	}

	// Log completion with rows affected and duration
	duration := time.Since(start)
	log.Debug("query completed", "rows_affected", rowsAffected, "duration", duration)

	return &QueryResult{
		Columns:      []string{"rows_affected"},
		Rows:         []map[string]interface{}{{"rows_affected": rowsAffected}},
		RowsAffected: rowsAffected,
	}, nil
}

// ExecuteReadOnlyQuery executes a read-only SQL query and returns results with column order preserved.
// Deprecated: Use ExecuteQuery instead which handles both reads and writes.
func (db *DB) ExecuteReadOnlyQuery(query string) (*QueryResult, error) {
	return db.ExecuteQuery(query)
}
