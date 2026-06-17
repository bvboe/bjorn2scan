package database

import (
	"database/sql"
	"fmt"
	"hash/fnv"
	"strings"
	"time"
)

// Package represents a package from the packages table
type Package struct {
	ID                int    `json:"id"`
	ImageID           int64  `json:"image_id"`
	Name              string `json:"name"`
	Version           string `json:"version"`
	Type              string `json:"type"`
	NumberOfInstances int    `json:"number_of_instances"`
	CreatedAt         string `json:"created_at"`
}

// Vulnerability represents a vulnerability from the vulnerabilities table
type Vulnerability struct {
	ID             int     `json:"id"`
	ImageID        int64   `json:"image_id"`
	CVEID          string  `json:"cve_id"`
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	PackageType    string  `json:"package_type"`
	Severity       string  `json:"severity"`
	FixStatus      string  `json:"fix_status"`
	FixedVersion   string  `json:"fixed_version"`
	Count          int     `json:"count"`
	CreatedAt      string  `json:"created_at"`
}

// ImageSummary represents the summary information for an image
// Deprecated: This struct is kept for backward compatibility but image_summary table no longer exists
type ImageSummary struct {
	ImageID      int64  `json:"image_id"`
	PackageCount int    `json:"package_count"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	UpdatedAt    string `json:"updated_at"`
}

// ImageDetails combines image metadata with summary statistics
type ImageDetails struct {
	ID        int64  `json:"id"`
	Digest    string `json:"digest"`
	Status    string `json:"status"` // Unified status field
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// Deprecated: Use Status instead
	ScanStatus          string `json:"scan_status,omitempty"`
	VulnerabilityStatus string `json:"vulnerability_status,omitempty"`
	ScannedAt           string `json:"scanned_at,omitempty"`

	// Summary data
	PackageCount       int    `json:"package_count"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	CriticalCount      int    `json:"critical_count"`
	HighCount          int    `json:"high_count"`
	MediumCount        int    `json:"medium_count"`
	LowCount           int    `json:"low_count"`
	OSName             string `json:"os_name,omitempty"`
	OSVersion          string `json:"os_version,omitempty"`
}

// GetPackagesByImage returns all packages for a specific image
func (db *DB) GetPackagesByImage(digest string) (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT p.id, p.image_id, p.name, p.version, p.type, p.number_of_instances, p.created_at
		FROM image_packages p
		JOIN images img ON p.image_id = img.id
		WHERE img.digest = ?
		ORDER BY p.name, p.version
	`, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to query packages: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	var packages []Package
	for rows.Next() {
		var pkg Package
		err := rows.Scan(&pkg.ID, &pkg.ImageID, &pkg.Name, &pkg.Version, &pkg.Type,
			&pkg.NumberOfInstances, &pkg.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetVulnerabilitiesByImage returns all vulnerabilities for a specific image
func (db *DB) GetVulnerabilitiesByImage(digest string) (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT v.id, v.image_id, v.cve_id, v.package_name, v.package_version, v.package_type,
		       v.severity, v.fix_status, v.fixed_version, v.count, v.created_at
		FROM image_vulnerabilities v
		JOIN images img ON v.image_id = img.id
		WHERE img.digest = ?
		ORDER BY
			CASE v.severity
				WHEN 'Critical' THEN 1
				WHEN 'High' THEN 2
				WHEN 'Medium' THEN 3
				WHEN 'Low' THEN 4
				WHEN 'Negligible' THEN 5
				ELSE 6
			END,
			v.cve_id
	`, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	var vulns []Vulnerability
	for rows.Next() {
		var vuln Vulnerability
		err := rows.Scan(&vuln.ID, &vuln.ImageID, &vuln.CVEID, &vuln.PackageName,
			&vuln.PackageVersion, &vuln.PackageType, &vuln.Severity, &vuln.FixStatus,
			&vuln.FixedVersion, &vuln.Count, &vuln.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// GetImageSummary returns summary information for a specific image
// Package count is calculated dynamically from the packages table
func (db *DB) GetImageSummary(digest string) (interface{}, error) {
	var summary ImageSummary
	err := db.conn.QueryRow(`
		SELECT
			img.id,
			(SELECT COUNT(*) FROM image_packages WHERE image_id = img.id) as package_count,
			img.os_name,
			img.os_version,
			img.updated_at
		FROM images img
		WHERE img.digest = ?
	`, digest).Scan(&summary.ImageID, &summary.PackageCount, &summary.OSName,
		&summary.OSVersion, &summary.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil // No image found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image summary: %w", err)
	}

	return &summary, nil
}

// GetImageDetails returns detailed information including vulnerability counts
func (db *DB) GetImageDetails(digest string) (interface{}, error) {
	log.Debug("get image details", "digest", digest, "digest_len", len(digest))
	var details ImageDetails
	var scannedAt sql.NullString
	var osName, osVersion sql.NullString

	// Get basic image info and calculate package count dynamically
	err := db.conn.QueryRow(`
		SELECT
			img.id, img.digest, img.status,
			img.created_at, img.updated_at, img.sbom_scanned_at,
			(SELECT COUNT(*) FROM image_packages WHERE image_id = img.id),
			COALESCE(img.os_name, ''),
			COALESCE(img.os_version, '')
		FROM images img
		WHERE img.digest = ?
	`, digest).Scan(&details.ID, &details.Digest, &details.Status,
		&details.CreatedAt, &details.UpdatedAt, &scannedAt, &details.PackageCount,
		&osName, &osVersion)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("image not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get image details: %w", err)
	}

	if scannedAt.Valid {
		details.ScannedAt = scannedAt.String
	}
	if osName.Valid {
		details.OSName = osName.String
	}
	if osVersion.Valid {
		details.OSVersion = osVersion.String
	}

	// Get vulnerability counts by severity
	rows, err := db.conn.Query(`
		SELECT
			LOWER(severity),
			SUM(count) as total
		FROM image_vulnerabilities
		WHERE image_id = ?
		GROUP BY LOWER(severity)
	`, details.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability counts: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	totalVulns := 0
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability count: %w", err)
		}

		totalVulns += count
		switch severity {
		case "critical":
			details.CriticalCount = count
		case "high":
			details.HighCount = count
		case "medium":
			details.MediumCount = count
		case "low", "negligible":
			details.LowCount += count
		}
	}

	details.VulnerabilityCount = totalVulns

	return &details, nil
}

// GetAllImageDetails returns detailed information for all images
func (db *DB) GetAllImageDetails() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT
			img.id, img.digest, img.status,
			img.created_at, img.updated_at, img.sbom_scanned_at,
			COUNT(DISTINCT p.id) as package_count,
			COALESCE(img.os_name, ''),
			COALESCE(img.os_version, ''),
			COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'critical' THEN v.count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'high' THEN v.count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN LOWER(v.severity) = 'medium' THEN v.count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN LOWER(v.severity) IN ('low', 'negligible') THEN v.count ELSE 0 END), 0),
			COALESCE(SUM(v.count), 0) as vuln_count
		FROM images img
		LEFT JOIN image_packages p ON p.image_id = img.id
		LEFT JOIN image_vulnerabilities v ON v.image_id = img.id
		GROUP BY img.id
		ORDER BY img.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	var images []ImageDetails
	for rows.Next() {
		var details ImageDetails
		var scannedAt sql.NullString
		var osName, osVersion sql.NullString

		err := rows.Scan(
			&details.ID, &details.Digest, &details.Status,
			&details.CreatedAt, &details.UpdatedAt, &scannedAt,
			&details.PackageCount, &osName, &osVersion,
			&details.CriticalCount, &details.HighCount, &details.MediumCount,
			&details.LowCount, &details.VulnerabilityCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image row: %w", err)
		}

		if scannedAt.Valid {
			details.ScannedAt = scannedAt.String
		}
		if osName.Valid {
			details.OSName = osName.String
		}
		if osVersion.Valid {
			details.OSVersion = osVersion.String
		}

		images = append(images, details)
	}

	return images, nil
}

// GetLastUpdatedTimestamp returns a change-detection signature for the UI poll
// endpoint (/api/lastupdated). The signature is maintained in-memory and updated
// by notifyWrite() after every write operation, so this call never touches the DB.
// dataType is accepted for interface compatibility but is not used.
func (db *DB) GetLastUpdatedTimestamp(_ string) (string, error) {
	db.cachesMu.RLock()
	sig := db.lastUpdatedSig
	db.cachesMu.RUnlock()
	return sig, nil
}

// FilterOptions holds cached distinct values for image filter dropdowns.
type FilterOptions struct {
	Namespaces   []string
	OSNames      []string
	VulnStatuses []string
	PackageTypes []string
}

// GetFilterOptions returns image filter options, serving from in-memory cache
// when available. The cache is invalidated on every write by notifyWrite().
func (db *DB) GetFilterOptions() (*FilterOptions, error) {
	db.cachesMu.RLock()
	cached := db.filterOpts
	db.cachesMu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	opts := &FilterOptions{
		Namespaces:   make([]string, 0),
		OSNames:      make([]string, 0),
		VulnStatuses: make([]string, 0),
		PackageTypes: make([]string, 0),
	}

	type querySpec struct {
		sql  string
		dest *[]string
	}
	queries := []querySpec{
		{"SELECT DISTINCT namespace FROM containers WHERE namespace IS NOT NULL AND namespace != '' ORDER BY namespace", &opts.Namespaces},
		{"SELECT DISTINCT os_name FROM images WHERE os_name IS NOT NULL AND os_name != '' ORDER BY os_name", &opts.OSNames},
		{"SELECT DISTINCT fix_status FROM image_vulnerabilities WHERE fix_status IS NOT NULL AND fix_status != '' ORDER BY fix_status", &opts.VulnStatuses},
		{"SELECT DISTINCT type FROM image_packages WHERE type IS NOT NULL AND type != '' ORDER BY type", &opts.PackageTypes},
	}

	for _, q := range queries {
		rows, err := db.conn.Query(q.sql)
		if err != nil {
			return nil, fmt.Errorf("failed to query filter options: %w", err)
		}
		for rows.Next() {
			var val string
			if err := rows.Scan(&val); err == nil && val != "" {
				*q.dest = append(*q.dest, val)
			}
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("failed to close filter options rows: %w", err)
		}
	}

	db.cachesMu.Lock()
	db.filterOpts = opts
	db.cachesMu.Unlock()
	return opts, nil
}

// ScannedContainer represents a container for metrics
type ScannedContainer struct {
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	Name         string `json:"name"`
	NodeName     string `json:"node_name"`
	Reference    string `json:"reference"`
	Digest       string `json:"digest"`
	OSName       string `json:"os_name"`
	Architecture string `json:"architecture"`
}


// ImageScanStatusCount represents the count of images by scan status
type ImageScanStatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// GetImageScanStatusCounts returns the count of running images grouped by scan status
// Only counts images that have at least one running container
func (db *DB) GetImageScanStatusCounts() ([]ImageScanStatusCount, error) {
	// Get all possible statuses from scan_status table
	statusRows, err := db.conn.Query(`
		SELECT status FROM scan_status ORDER BY sort_order
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan statuses: %w", err)
	}

	var allStatuses []string
	for statusRows.Next() {
		var status string
		if err := statusRows.Scan(&status); err != nil {
			_ = statusRows.Close()
			return nil, fmt.Errorf("failed to scan status row: %w", err)
		}
		allStatuses = append(allStatuses, status)
	}
	if err := statusRows.Close(); err != nil {
		log.Warn("failed to close status rows", "error", err)
	}

	// Get counts for running images (images with at least one container)
	rows, err := db.conn.Query(`
		SELECT
			img.status,
			COUNT(DISTINCT img.id) as count
		FROM images img
		INNER JOIN containers c ON c.image_id = img.id
		GROUP BY img.status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query image scan status counts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Build a map of status -> count
	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count row: %w", err)
		}
		statusCounts[status] = count
	}

	// Build result with all statuses (including zeros)
	result := make([]ImageScanStatusCount, 0, len(allStatuses))
	for _, status := range allStatuses {
		result = append(result, ImageScanStatusCount{
			Status: status,
			Count:  statusCounts[status], // defaults to 0 if not in map
		})
	}

	return result, nil
}

// ContainerVulnerability represents a vulnerability found in a running container
type ContainerVulnerability struct {
	VulnID         int64   `json:"vuln_id"`
	Namespace      string  `json:"namespace"`
	Pod            string  `json:"pod"`
	Name           string  `json:"name"`
	NodeName       string  `json:"node_name"`
	Reference      string  `json:"reference"`
	Digest         string  `json:"digest"`
	OSName         string  `json:"os_name"`
	CVEID          string  `json:"cve_id"`
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	Severity       string  `json:"severity"`
	FixStatus      string  `json:"fix_status"`
	FixedVersion   string  `json:"fixed_version"`
	Count          int     `json:"count"`
	KnownExploited int     `json:"known_exploited"`
	Risk           float64 `json:"risk"`
}


// LoadMetricStaleness loads the metric staleness data from the database
// Returns empty string if no data exists
func (db *DB) LoadMetricStaleness(key string) (string, error) {
	var data string
	err := db.conn.QueryRow(`SELECT data FROM app_state WHERE key = ?`, key).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to load metric staleness: %w", err)
	}
	return data, nil
}

// SaveMetricStaleness saves the metric staleness data to the database
// Uses INSERT OR REPLACE to handle both insert and update cases
func (db *DB) SaveMetricStaleness(key string, data string) error {
	done := db.beginWrite("upsert_staleness")
	defer done()
	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO app_state (key, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`, key, data)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to save metric staleness: %w", err)
	}
	return nil
}

// StalenessRow represents a single row in the metric_staleness table.
// ExpiresAtUnix is nil for active metrics. It is set to an expiry timestamp when a metric
// disappears; after that time the row is deleted and NaN emission stops.
type StalenessRow struct {
	MetricKey     string // "familyName|label1=v1|label2=v2|..." — unique key for this metric point
	FamilyName    string // Prometheus metric family name (e.g. "bjorn2scan_image_vulnerability")
	LabelsJSON    string // JSON-encoded label map, used to reconstruct NaN lines for stale metrics
	ExpiresAtUnix *int64 // nil = active; non-nil = expiry timestamp (set when metric disappears)
	KeyHash       uint64 // FNV-1a 64-bit of MetricKey; PRIMARY KEY in metric_staleness; computed lazily by HashMetricKey
}

// HashMetricKey returns a deterministic 64-bit hash of the metric key. It is used
// as the PRIMARY KEY in the metric_staleness table so that the in-memory diff
// cache can store ~9MB of map[uint64]int64 instead of ~200MB of full keys.
// FNV-1a is deterministic across processes (no per-run seed) and has good
// distribution. Collision probability at 371k keys is ~7.5×10⁻⁶, acceptable for
// non-adversarial bookkeeping where a collision would cost at most one cycle of
// incorrect staleness signaling.
func HashMetricKey(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return h.Sum64()
}

// StreamScannedContainers calls callback for each completed container scan row.
// This is the streaming variant of GetScannedContainers, used for memory-efficient metrics generation.
func (db *DB) StreamScannedContainers(callback func(ScannedContainer) error) error {
	return trackRead("stream_scanned_containers", func() error {
		rows, err := db.conn.Query(`
			SELECT
				c.namespace,
				c.pod,
				c.name,
				c.node_name,
				c.reference,
				img.digest,
				COALESCE(img.os_name, '') as os_name,
				COALESCE(img.architecture, '') as architecture
			FROM containers c
			JOIN images img ON c.image_id = img.id
			WHERE img.status = 'completed'
			ORDER BY c.namespace, c.pod, c.name
		`)
		if err != nil {
			return fmt.Errorf("failed to query scanned containers: %w", err)
		}
		defer func() {
			if err := rows.Close(); err != nil {
				log.Warn("failed to close rows", "error", err)
			}
		}()

		for rows.Next() {
			var sc ScannedContainer
			if err := rows.Scan(
				&sc.Namespace,
				&sc.Pod,
				&sc.Name,
				&sc.NodeName,
				&sc.Reference,
				&sc.Digest,
				&sc.OSName,
				&sc.Architecture,
			); err != nil {
				return fmt.Errorf("failed to scan container row: %w", err)
			}
			if err := callback(sc); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

// StreamContainerVulnerabilities calls callback for each vulnerability in a running
// container. On a warm cache it serves entirely from memory with no DB I/O. On a
// cold start it falls back to a direct DB read and triggers an async cache rebuild
// so that subsequent calls hit the fast path.
func (db *DB) StreamContainerVulnerabilities(callback func(ContainerVulnerability) error) error {
	db.cachesMu.RLock()
	cached := db.containerVulnRows
	db.cachesMu.RUnlock()

	if cached != nil {
		for _, v := range cached {
			if err := callback(v); err != nil {
				return err
			}
		}
		return nil
	}

	// Cold path: cache not yet built. Read directly from DB and schedule a
	// background rebuild so the next call hits the fast path.
	go db.rebuildContainerVulnCache()
	return trackRead("stream_container_vulnerabilities", func() error {
		return db.readContainerVulnsFromDB(callback)
	})
}

// readContainerVulnsFromDB is the raw DB read used by both the cold path of
// StreamContainerVulnerabilities and rebuildContainerVulnCache.
func (db *DB) readContainerVulnsFromDB(callback func(ContainerVulnerability) error) error {
	rows, err := db.conn.Query(`
		SELECT
			v.id,
			c.namespace,
			c.pod,
			c.name,
			c.node_name,
			c.reference,
			img.digest,
			COALESCE(img.os_name, '') as os_name,
			v.cve_id,
			COALESCE(v.package_name, '') as package_name,
			COALESCE(v.package_version, '') as package_version,
			COALESCE(v.severity, '') as severity,
			COALESCE(v.fix_status, '') as fix_status,
			COALESCE(v.fixed_version, '') as fixed_version,
			v.count,
			v.known_exploited,
			v.risk
		FROM containers c
		JOIN images img ON c.image_id = img.id
		JOIN image_vulnerabilities v ON img.id = v.image_id
		WHERE img.status = 'completed'
		ORDER BY c.namespace, c.pod, c.name, v.severity, v.cve_id
	`)
	if err != nil {
		return fmt.Errorf("failed to query container vulnerabilities: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close rows", "error", err)
		}
	}()

	for rows.Next() {
		var cv ContainerVulnerability
		if err := rows.Scan(
			&cv.VulnID,
			&cv.Namespace,
			&cv.Pod,
			&cv.Name,
			&cv.NodeName,
			&cv.Reference,
			&cv.Digest,
			&cv.OSName,
			&cv.CVEID,
			&cv.PackageName,
			&cv.PackageVersion,
			&cv.Severity,
			&cv.FixStatus,
			&cv.FixedVersion,
			&cv.Count,
			&cv.KnownExploited,
			&cv.Risk,
		); err != nil {
			return fmt.Errorf("failed to scan container vulnerability row: %w", err)
		}
		if err := callback(cv); err != nil {
			return err
		}
	}
	return rows.Err()
}

// QueryStaleness returns rows in the stale grace period: expires_at_unix is set and
// has not yet passed. These metrics should emit NaN to signal staleness to Prometheus.
func (db *DB) QueryStaleness(cycleStart int64) ([]StalenessRow, error) {
	rows, err := db.conn.Query(`
		SELECT metric_key, family_name, labels_json, expires_at_unix
		FROM metric_staleness
		WHERE expires_at_unix IS NOT NULL AND expires_at_unix > ?
		ORDER BY family_name, metric_key
	`, cycleStart)
	if err != nil {
		return nil, fmt.Errorf("failed to query staleness: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close staleness rows", "error", err)
		}
	}()

	var result []StalenessRow
	for rows.Next() {
		var r StalenessRow
		var expiresAt int64
		if err := rows.Scan(&r.MetricKey, &r.FamilyName, &r.LabelsJSON, &expiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan staleness row: %w", err)
		}
		r.ExpiresAtUnix = &expiresAt
		result = append(result, r)
	}
	return result, rows.Err()
}

// HydrateStalenessState reads (key_hash, expires_at_unix) for every row in the
// metric_staleness table. Called once at StalenessStore construction so that
// subsequent ApplyDiff cycles can compute their diff against an in-memory map
// instead of re-reading the entire table on every collection. Returns a fresh
// map keyed by FNV-64a hash of metric_key with value 0 for active rows or the
// expiry timestamp for stale-but-still-in-grace rows.
func (db *DB) HydrateStalenessState() (map[uint64]int64, error) {
	rows, err := db.conn.Query(`SELECT key_hash, expires_at_unix FROM metric_staleness`)
	if err != nil {
		return nil, fmt.Errorf("failed to hydrate staleness state: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("failed to close hydrate rows", "error", err)
		}
	}()

	state := make(map[uint64]int64, 1024)
	for rows.Next() {
		var hash int64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&hash, &expiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan hydrate row: %w", err)
		}
		if expiresAt.Valid {
			state[uint64(hash)] = expiresAt.Int64
		} else {
			state[uint64(hash)] = 0 // active sentinel
		}
	}
	return state, rows.Err()
}

// ApplyStalenessChanges commits the staleness diff in a single transaction.
// toUpsert covers both newly-seen metrics and previously-stale metrics that
// reappeared (UPSERT collapses the two cases). toStale lists key hashes for
// metrics that disappeared and now need an expiry timestamp set so Prometheus
// receives a final NaN marker. Either or both may be empty; the caller is
// responsible for skipping the call when nothing changed.
func (db *DB) ApplyStalenessChanges(toUpsert []StalenessRow, toStale []uint64, expiresAtUnix int64) error {
	if len(toUpsert) == 0 && len(toStale) == 0 {
		return nil
	}

	done := db.beginWrite("apply_staleness_diff")
	defer done()

	tx, err := db.conn.Begin()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// UPSERT new and reactivated rows. ON CONFLICT(key_hash) handles both
	// "previously stale, now active" (UPDATE expires_at_unix=NULL) and
	// "metadata refreshed" (rare; labels_json/family/key shouldn't drift but
	// the UPSERT keeps the row consistent if they do).
	if len(toUpsert) > 0 {
		const cols = 4
		const chunkSize = 200 // 200 × 4 = 800 params, well under SQLite's 999 default
		for start := 0; start < len(toUpsert); start += chunkSize {
			end := start + chunkSize
			if end > len(toUpsert) {
				end = len(toUpsert)
			}
			chunk := toUpsert[start:end]

			args := make([]any, 0, len(chunk)*cols)
			placeholders := make([]string, 0, len(chunk))
			for _, r := range chunk {
				placeholders = append(placeholders, "(?,?,?,?)")
				args = append(args, int64(r.KeyHash), r.MetricKey, r.FamilyName, r.LabelsJSON)
			}

			query := "INSERT INTO metric_staleness (key_hash, metric_key, family_name, labels_json) VALUES " +
				strings.Join(placeholders, ",") +
				" ON CONFLICT(key_hash) DO UPDATE SET expires_at_unix=NULL, metric_key=excluded.metric_key, family_name=excluded.family_name, labels_json=excluded.labels_json"
			if _, err := tx.Exec(query, args...); err != nil {
				exitOnCorruption(err)
				return fmt.Errorf("failed to upsert staleness rows: %w", err)
			}
		}
	}

	// Mark disappeared rows as stale. WHERE key_hash IN (...) is fast on the
	// PRIMARY KEY index — no full table scan, no metric_key string comparisons.
	if len(toStale) > 0 {
		const chunkSize = 500
		for start := 0; start < len(toStale); start += chunkSize {
			end := start + chunkSize
			if end > len(toStale) {
				end = len(toStale)
			}
			chunk := toStale[start:end]

			args := make([]any, 0, 1+len(chunk))
			args = append(args, expiresAtUnix)
			placeholders := make([]string, len(chunk))
			for i, h := range chunk {
				placeholders[i] = "?"
				args = append(args, int64(h))
			}

			query := "UPDATE metric_staleness SET expires_at_unix = ? WHERE key_hash IN (" +
				strings.Join(placeholders, ",") + ")"
			if _, err := tx.Exec(query, args...); err != nil {
				exitOnCorruption(err)
				return fmt.Errorf("failed to mark staleness rows stale: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit apply_staleness_diff: %w", err)
	}
	return nil
}

// DeleteExpiredStaleness removes rows whose expires_at_unix has passed.
// Called asynchronously after each collection cycle.
func (db *DB) DeleteExpiredStaleness(expireBefore int64) error {
	done := db.beginWrite("delete_expired_staleness")
	defer done()
	_, err := db.conn.Exec(
		`DELETE FROM metric_staleness WHERE expires_at_unix IS NOT NULL AND expires_at_unix < ?`,
		expireBefore,
	)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete expired staleness: %w", err)
	}
	return nil
}

// grypeDBTimestampKey is the key used to store the grype DB timestamp in app_state table
const grypeDBTimestampKey = "grype_db_timestamp"

// LoadGrypeDBTimestamp loads the last known grype vulnerability database timestamp
// Returns zero time if no timestamp has been stored yet
func (db *DB) LoadGrypeDBTimestamp() (time.Time, error) {
	var data string
	err := db.conn.QueryRow(`SELECT data FROM app_state WHERE key = ?`, grypeDBTimestampKey).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, nil // No timestamp stored yet
		}
		return time.Time{}, fmt.Errorf("failed to load grype DB timestamp: %w", err)
	}
	if data == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, data)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse grype DB timestamp: %w", err)
	}
	return t, nil
}

// SaveGrypeDBTimestamp saves the grype vulnerability database timestamp
func (db *DB) SaveGrypeDBTimestamp(t time.Time) error {
	done := db.beginWrite("update_last_scanned_at")
	defer done()
	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO app_state (key, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
	`, grypeDBTimestampKey, t.Format(time.RFC3339))
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to save grype DB timestamp: %w", err)
	}
	return nil
}

// GetImagesNeedingRescan returns completed images that were scanned with an older
// grype vulnerability database, or have never been scanned with a tracked version.
// Only returns images that have at least one running container — orphaned images
// (no containers) are skipped since there is nothing to rescan them against.
// This enables intelligent rescanning when the vulnerability database is updated.
func (db *DB) GetImagesNeedingRescan(currentGrypeDBBuilt time.Time) ([]ContainerImage, error) {
	if currentGrypeDBBuilt.IsZero() {
		return nil, nil // No current DB timestamp, can't determine what needs rescanning
	}

	currentTimestamp := currentGrypeDBBuilt.UTC().Format(time.RFC3339)

	// Include both 'completed' and 'vuln_scan_failed' images. A failed image
	// might have failed precisely because of a stale or broken grype DB;
	// retrying with a fresh DB is exactly what we want. SBOM presence is the
	// gate — without an SBOM we have nothing to scan.
	rows, err := db.conn.Query(`
		SELECT DISTINCT i.id, i.digest, i.created_at, i.updated_at
		FROM images i
		INNER JOIN containers c ON c.image_id = i.id
		WHERE i.status IN (?, ?)
		  AND (i.sbom_compressed IS NOT NULL OR (i.sbom IS NOT NULL AND i.sbom != ''))
		  AND (i.grype_db_built IS NULL OR i.grype_db_built < ?)
		ORDER BY i.created_at DESC
	`, StatusCompleted.String(), StatusVulnScanFailed.String(), currentTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to query images needing rescan: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		err := rows.Scan(&img.ID, &img.Digest, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		images = append(images, img)
	}

	return images, rows.Err()
}
