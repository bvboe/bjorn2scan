package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// GetImageStatus returns the unified status for an image by digest
// Returns: Status constant (pending, generating_sbom, sbom_failed, sbom_unavailable,
//          scanning_vulnerabilities, vuln_scan_failed, completed)
func (db *DB) GetImageStatus(digest string) (Status, error) {
	var status string
	err := db.conn.QueryRow(`
		SELECT status FROM images
		WHERE digest = ?
	`, digest).Scan(&status)

	if err == sql.ErrNoRows {
		return StatusPending, nil // Image not found means pending
	}
	if err != nil {
		return "", fmt.Errorf("failed to get status: %w", err)
	}

	return Status(status), nil
}

// GetImageScanStatusBulk returns scan status for multiple image digests in a single query.
// Returns a map of digest -> status string. Missing digests are returned as "pending".
func (db *DB) GetImageScanStatusBulk(digests []string) (map[string]string, error) {
	result := make(map[string]string, len(digests))

	// Initialize all digests as pending (for any not found in DB)
	for _, digest := range digests {
		result[digest] = "pending"
	}

	if len(digests) == 0 {
		return result, nil
	}

	// Build query with placeholders
	placeholders := make([]string, len(digests))
	args := make([]interface{}, len(digests))
	for i, digest := range digests {
		placeholders[i] = "?"
		args[i] = digest
	}

	query := fmt.Sprintf(`
		SELECT digest, status FROM images
		WHERE digest IN (%s)
	`, joinStrings(placeholders, ","))

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query image statuses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var digest, status string
		if err := rows.Scan(&digest, &status); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Map new status to old scan_status (same logic as GetImageScanStatus)
		switch Status(status) {
		case StatusCompleted, StatusScanningVulnerabilities, StatusVulnScanFailed:
			result[digest] = "scanned"
		case StatusGeneratingSBOM:
			result[digest] = "scanning"
		case StatusSBOMFailed, StatusSBOMUnavailable:
			result[digest] = "failed"
		default:
			result[digest] = "pending"
		}
	}

	return result, rows.Err()
}

// IsScanDataCompleteBulk checks scan completeness for multiple image digests in a single query.
// Returns a map of digest -> bool. Missing digests are returned as false.
func (db *DB) IsScanDataCompleteBulk(digests []string) (map[string]bool, error) {
	result := make(map[string]bool, len(digests))

	// Initialize all digests as incomplete (for any not found in DB)
	for _, digest := range digests {
		result[digest] = false
	}

	if len(digests) == 0 {
		return result, nil
	}

	// Build query with placeholders
	placeholders := make([]string, len(digests))
	args := make([]interface{}, len(digests))
	for i, digest := range digests {
		placeholders[i] = "?"
		args[i] = digest
	}

	query := fmt.Sprintf(`
		SELECT
			digest,
			status,
			(sbom_compressed IS NOT NULL OR (sbom IS NOT NULL AND LENGTH(sbom) > 0)),
			(vulnerabilities_compressed IS NOT NULL OR (vulnerabilities IS NOT NULL AND LENGTH(vulnerabilities) > 0))
		FROM images
		WHERE digest IN (%s)
	`, joinStrings(placeholders, ","))

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan data completeness: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var digest, status string
		var hasSBOM, hasVulns bool
		if err := rows.Scan(&digest, &status, &hasSBOM, &hasVulns); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Data is complete only if status is completed AND we have both SBOM and vulnerabilities
		result[digest] = status == string(StatusCompleted) && hasSBOM && hasVulns
	}

	return result, rows.Err()
}

// joinStrings joins strings with a separator (helper to avoid importing strings package)
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// GetImageScanStatus is deprecated, use GetImageStatus instead
// Provided for backward compatibility during migration
func (db *DB) GetImageScanStatus(digest string) (string, error) {
	status, err := db.GetImageStatus(digest)
	if err != nil {
		return "", err
	}

	// Map new status to old scan_status
	switch status {
	case StatusCompleted, StatusScanningVulnerabilities, StatusVulnScanFailed:
		return "scanned", nil
	case StatusGeneratingSBOM:
		return "scanning", nil
	case StatusSBOMFailed, StatusSBOMUnavailable:
		return "failed", nil
	default:
		return "pending", nil
	}
}

// IsScanDataComplete checks if an image has complete scan data (SBOM and vulnerabilities)
// Returns true only if status is "completed" AND both SBOM and vulnerability data exist
func (db *DB) IsScanDataComplete(digest string) (bool, error) {
	var status string
	var hasSBOM bool
	var hasVulns bool

	err := db.conn.QueryRow(`
		SELECT
			status,
			(sbom_compressed IS NOT NULL OR (sbom IS NOT NULL AND LENGTH(sbom) > 0)),
			(vulnerabilities_compressed IS NOT NULL OR (vulnerabilities IS NOT NULL AND LENGTH(vulnerabilities) > 0))
		FROM images
		WHERE digest = ?
	`, digest).Scan(&status, &hasSBOM, &hasVulns)

	if err == sql.ErrNoRows {
		return false, nil // Image not found means incomplete
	}
	if err != nil {
		return false, fmt.Errorf("failed to check scan data completeness: %w", err)
	}

	// Data is complete only if status is completed AND we have both SBOM and vulnerabilities
	return status == string(StatusCompleted) && hasSBOM && hasVulns, nil
}

// UpdateStatus updates the unified status for an image
func (db *DB) UpdateStatus(digest string, status Status, errorMsg string) error {
	var sbomScannedAt, vulnsScannedAt interface{}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Set timestamps based on status
	switch status {
	case StatusScanningVulnerabilities, StatusSBOMFailed, StatusSBOMUnavailable:
		// SBOM stage just completed (success or failure)
		sbomScannedAt = timestamp
	case StatusCompleted, StatusVulnScanFailed:
		// Vulnerability scan just completed (success or failure)
		vulnsScannedAt = timestamp
	}

	done := db.beginWrite("update_status")
	defer done()
	_, err := db.conn.Exec(`
		UPDATE images
		SET status = ?,
		    status_error = ?,
		    sbom_scanned_at = COALESCE(sbom_scanned_at, ?),
		    vulns_scanned_at = COALESCE(vulns_scanned_at, ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, status.String(), errorMsg, sbomScannedAt, vulnsScannedAt, digest)

	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to update status: %w", err)
	}

	db.notifyWrite()
	return nil
}

// UpdateScanStatus is deprecated, use UpdateStatus instead
// Provided for backward compatibility during migration
func (db *DB) UpdateScanStatus(digest string, status string, errorMsg string) error {
	// Map old status to new unified status
	var newStatus Status
	switch status {
	case "scanning":
		newStatus = StatusGeneratingSBOM
	case "scanned":
		newStatus = StatusScanningVulnerabilities
	case "failed":
		newStatus = StatusSBOMFailed
	default:
		newStatus = StatusPending
	}

	return db.UpdateStatus(digest, newStatus, errorMsg)
}

// StoreSBOM stores the SBOM JSON for an image and marks it as scanned
func (db *DB) StoreSBOM(digest string, sbomJSON []byte) error {
	// Get image ID first (read-only, outside any lock).
	var imageID int64
	err := db.conn.QueryRow(`SELECT id FROM images WHERE digest = ?`, digest).Scan(&imageID)
	if err != nil {
		return fmt.Errorf("failed to get image ID: %w", err)
	}

	// Compress blob before acquiring any lock.
	compressStart := time.Now()
	sbomCompressed, err := compressGzip(sbomJSON)
	if err != nil {
		return fmt.Errorf("failed to compress SBOM: %w", err)
	}
	compressMs := time.Since(compressStart).Milliseconds()

	// Update image status — tiny write, no blob.
	storeDone := db.beginWrite("store_sbom")
	_, err = db.conn.Exec(`
		UPDATE images
		SET status = ?,
		    status_error = NULL,
		    sbom_scanned_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, StatusScanningVulnerabilities.String(), time.Now().UTC().Format(time.RFC3339), digest)
	storeDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to update SBOM status: %w", err)
	}

	// Parse and store SBOM data with batch inserts (acquires writeMu internally).
	if err = parseSBOMData(db, imageID, sbomJSON); err != nil {
		log.Warn("failed to parse SBOM data", "digest", digest, "error", err)
	}

	// Write compressed blob in its own separate write.
	blobStart := time.Now()
	blobDone := db.beginWrite("store_sbom_blob")
	_, err = db.conn.Exec(`UPDATE images SET sbom_compressed = ? WHERE id = ?`, sbomCompressed, imageID)
	blobDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to store compressed SBOM: %w", err)
	}
	blobMs := time.Since(blobStart).Milliseconds()

	log.Info("stored SBOM for image",
		"digest", digest[:min(16, len(digest))],
		"compress_ms", compressMs,
		"blob_compressed_kb", len(sbomCompressed)/1024,
		"blob_write_ms", blobMs,
	)
	db.notifyWrite()
	return nil
}

// GetSBOM retrieves the SBOM JSON for an image by digest.
// Returns the gzip-compressed version if available, otherwise falls back to the
// uncompressed column (written by older scanner versions).
func (db *DB) GetSBOM(digest string) ([]byte, error) {
	var compressed []byte
	var raw sql.NullString
	err := db.conn.QueryRow(`SELECT sbom_compressed, sbom FROM images WHERE digest = ?`, digest).Scan(&compressed, &raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}
	if len(compressed) > 0 {
		return decompressGzip(compressed)
	}
	if raw.Valid && raw.String != "" {
		return []byte(raw.String), nil
	}
	return nil, fmt.Errorf("SBOM not available")
}

// GetImagesByScanStatus is deprecated, use GetImagesByStatus instead
// Returns all images with a specific scan status (maps old status to new unified status)
func (db *DB) GetImagesByScanStatus(status string) ([]ContainerImage, error) {
	// Map old status values to new unified status values
	var statusFilter string
	switch status {
	case "pending":
		// Include pending and generating_sbom
		statusFilter = "status IN ('pending', 'generating_sbom')"
	case "scanning":
		statusFilter = "status = 'generating_sbom'"
	case "scanned":
		// Include all statuses that indicate SBOM is complete
		statusFilter = "status IN ('scanning_vulnerabilities', 'vuln_scan_failed', 'completed')"
	case "failed":
		// Include all failure statuses
		statusFilter = "status IN ('sbom_failed', 'sbom_unavailable', 'vuln_scan_failed')"
	default:
		return nil, fmt.Errorf("unknown scan status: %s", status)
	}

	rows, err := db.conn.Query(`
		SELECT id, digest, created_at, updated_at
		FROM images
		WHERE `+statusFilter+`
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images by scan status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		err := rows.Scan(&img.ID, &img.Digest, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, nil
}

// GetImagesByStatus returns all images with a specific unified status
func (db *DB) GetImagesByStatus(status Status) ([]ContainerImage, error) {
	rows, err := db.conn.Query(`
		SELECT id, digest, created_at, updated_at
		FROM images
		WHERE status = ?
		ORDER BY created_at DESC
	`, status.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query images by status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		err := rows.Scan(&img.ID, &img.Digest, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}
		images = append(images, img)
	}

	return images, nil
}

// GetFirstContainerForImage returns the first container for a given image digest
// This is used to determine which node to scan from
func (db *DB) GetFirstContainerForImage(digest string) (*ContainerRow, error) {
	var row ContainerRow
	err := db.conn.QueryRow(`
		SELECT
			c.id, c.namespace, c.pod, c.name,
			c.reference, c.image_id, img.digest,
			c.created_at, c.node_name, c.container_runtime
		FROM containers c
		JOIN images img ON c.image_id = img.id
		WHERE img.digest = ?
		ORDER BY c.created_at ASC
		LIMIT 1
	`, digest).Scan(&row.ID, &row.Namespace, &row.Pod, &row.Name,
		&row.Reference, &row.ImageID, &row.Digest,
		&row.CreatedAt, &row.NodeName, &row.ContainerRuntime)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no containers found for image")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get first container: %w", err)
	}

	return &row, nil
}

// GetImageVulnerabilityStatus is deprecated, use GetImageStatus instead
// Provided for backward compatibility during migration
func (db *DB) GetImageVulnerabilityStatus(digest string) (string, error) {
	status, err := db.GetImageStatus(digest)
	if err != nil {
		return "", err
	}

	// Map new status to old vulnerability_status
	switch status {
	case StatusCompleted:
		return "scanned", nil
	case StatusScanningVulnerabilities:
		return "scanning", nil
	case StatusVulnScanFailed:
		return "failed", nil
	default:
		return "pending", nil
	}
}

// UpdateVulnerabilityStatus is deprecated, use UpdateStatus instead
// Provided for backward compatibility during migration
func (db *DB) UpdateVulnerabilityStatus(digest string, status string, errorMsg string) error {
	// Map old vulnerability status to new unified status
	var newStatus Status
	switch status {
	case "scanning":
		newStatus = StatusScanningVulnerabilities
	case "scanned":
		newStatus = StatusCompleted
	case "failed":
		newStatus = StatusVulnScanFailed
	default:
		// If called with pending, check if SBOM is ready
		imgStatus, _ := db.GetImageStatus(digest)
		if imgStatus.HasSBOM() {
			newStatus = StatusScanningVulnerabilities
		} else {
			newStatus = StatusPending
		}
	}

	return db.UpdateStatus(digest, newStatus, errorMsg)
}

// StoreVulnerabilities stores the vulnerability scan JSON for an image and marks it as scanned
// grypeDBBuilt is the build timestamp of the grype vulnerability database used for scanning (can be zero for unknown)
func (db *DB) StoreVulnerabilities(digest string, vulnJSON []byte, grypeDBBuilt time.Time) error {
	// Get image ID first
	var imageID int64
	err := db.conn.QueryRow(`SELECT id FROM images WHERE digest = ?`, digest).Scan(&imageID)
	if err != nil {
		return fmt.Errorf("failed to get image ID: %w", err)
	}

	// Extract grype DB timestamp from the scan JSON itself to ensure consistency
	// The JSON contains descriptor.db.status.built which is the authoritative source
	var grypeDBBuiltStr *string
	if extractedTime := extractGrypeDBBuiltFromJSON(vulnJSON); extractedTime != nil {
		s := extractedTime.UTC().Format(time.RFC3339)
		grypeDBBuiltStr = &s
	} else if !grypeDBBuilt.IsZero() {
		// Fallback to the passed parameter if extraction fails
		s := grypeDBBuilt.UTC().Format(time.RFC3339)
		grypeDBBuiltStr = &s
	}

	// Compress blob before acquiring any lock.
	compressStart := time.Now()
	vulnCompressed, err := compressGzip(vulnJSON)
	if err != nil {
		return fmt.Errorf("failed to compress vulnerability JSON: %w", err)
	}
	compressMs := time.Since(compressStart).Milliseconds()

	// Update image status — tiny write, no blob.
	vulnDone := db.beginWrite("store_vulnerabilities")
	_, err = db.conn.Exec(`
		UPDATE images
		SET status = ?,
		    status_error = NULL,
		    vulns_scanned_at = ?,
		    grype_db_built = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE digest = ?
	`, StatusCompleted.String(), time.Now().UTC().Format(time.RFC3339), grypeDBBuiltStr, digest)
	vulnDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to update vulnerability status: %w", err)
	}

	// Parse and store vulnerability data with batch inserts (acquires writeMu internally).
	if err = parseVulnerabilityData(db, imageID, vulnJSON); err != nil {
		log.Warn("failed to parse vulnerability data", "digest", digest, "error", err)
	}

	// Write compressed blob in its own separate write.
	blobStart := time.Now()
	blobDone := db.beginWrite("store_vulnerabilities_blob")
	_, err = db.conn.Exec(`UPDATE images SET vulnerabilities_compressed = ? WHERE id = ?`, vulnCompressed, imageID)
	blobDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to store compressed vulnerabilities: %w", err)
	}
	blobMs := time.Since(blobStart).Milliseconds()

	log.Info("stored vulnerabilities for image",
		"digest", digest[:min(16, len(digest))],
		"compress_ms", compressMs,
		"blob_compressed_kb", len(vulnCompressed)/1024,
		"blob_write_ms", blobMs,
	)
	db.notifyWrite()
	return nil
}

// extractGrypeDBBuiltFromJSON extracts the grype database build timestamp from the
// vulnerability scan JSON. This ensures the stored timestamp matches what's in the JSON.
// Returns nil if extraction fails.
func extractGrypeDBBuiltFromJSON(vulnJSON []byte) *time.Time {
	// Parse just enough of the JSON to get descriptor.db.status.built
	var doc struct {
		Descriptor struct {
			DB struct {
				Status struct {
					Built string `json:"built"`
				} `json:"status"`
			} `json:"db"`
		} `json:"descriptor"`
	}

	if err := json.Unmarshal(vulnJSON, &doc); err != nil {
		return nil
	}

	if doc.Descriptor.DB.Status.Built == "" {
		return nil
	}

	// Parse the timestamp - try RFC3339 first, then legacy formats
	t, err := time.Parse(time.RFC3339, doc.Descriptor.DB.Status.Built)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05-07:00", doc.Descriptor.DB.Status.Built)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05+00:00", doc.Descriptor.DB.Status.Built)
			if err != nil {
				return nil
			}
		}
	}

	return &t
}

// GetVulnerabilities retrieves the vulnerability scan JSON for an image by digest.
// Returns the gzip-compressed version if available, otherwise falls back to the
// uncompressed column (written by older scanner versions).
func (db *DB) GetVulnerabilities(digest string) ([]byte, error) {
	var compressed []byte
	var raw sql.NullString
	err := db.conn.QueryRow(`SELECT vulnerabilities_compressed, vulnerabilities FROM images WHERE digest = ?`, digest).Scan(&compressed, &raw)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}
	if len(compressed) > 0 {
		return decompressGzip(compressed)
	}
	if raw.Valid && raw.String != "" {
		return []byte(raw.String), nil
	}
	return nil, fmt.Errorf("vulnerabilities not available")
}
