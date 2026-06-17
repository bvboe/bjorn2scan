package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// NodeRow represents a node row from the database
type NodeRow struct {
	ID               int64
	Name             string
	Hostname         sql.NullString
	OSRelease        sql.NullString
	KernelVersion    sql.NullString
	Architecture     sql.NullString
	ContainerRuntime sql.NullString
	KubeletVersion   sql.NullString
	Status           sql.NullString
	StatusError      sql.NullString
	SBOMScannedAt    sql.NullTime
	VulnsScannedAt   sql.NullTime
	GrypeDBBuilt     sql.NullString
	CreatedAt        time.Time
	UpdatedAt        time.Time
	PackageCount     int
	VulnerabilityCount int
}

// AddNode adds a new node to the database or returns existing
// Returns true if a new node was created, false if it already existed
func (db *DB) AddNode(n nodes.Node) (bool, error) {
	// Read all mutable fields so we can skip the write if nothing changed.
	var existingHostname, existingOSRelease, existingKernelVersion string
	var existingArchitecture, existingContainerRuntime, existingKubeletVersion string
	err := db.conn.QueryRow(`
		SELECT
			COALESCE(hostname, ''), COALESCE(os_release, ''), COALESCE(kernel_version, ''),
			COALESCE(architecture, ''), COALESCE(container_runtime, ''), COALESCE(kubelet_version, '')
		FROM nodes WHERE name = ?
	`, n.Name).Scan(
		&existingHostname, &existingOSRelease, &existingKernelVersion,
		&existingArchitecture, &existingContainerRuntime, &existingKubeletVersion,
	)

	if err == nil {
		// Node already exists — skip write if nothing changed.
		if existingHostname == n.Hostname &&
			existingOSRelease == n.OSRelease &&
			existingKernelVersion == n.KernelVersion &&
			existingArchitecture == n.Architecture &&
			existingContainerRuntime == n.ContainerRuntime &&
			existingKubeletVersion == n.KubeletVersion {
			return false, nil
		}
		done := db.beginWrite("add_node")
		_, err = db.conn.Exec(`
			UPDATE nodes SET
				hostname = ?,
				os_release = ?,
				kernel_version = ?,
				architecture = ?,
				container_runtime = ?,
				kubelet_version = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE name = ?
		`, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture,
			n.ContainerRuntime, n.KubeletVersion, n.Name)
		done()
		if err != nil {
			exitOnCorruption(err)
			return false, fmt.Errorf("failed to update node: %w", err)
		}
		db.notifyWrite()
		return false, nil
	}

	if err != sql.ErrNoRows {
		return false, fmt.Errorf("failed to query node: %w", err)
	}

	// Node doesn't exist, create it.
	done := db.beginWrite("add_node")
	result, err := db.conn.Exec(`
		INSERT INTO nodes (name, hostname, os_release, kernel_version, architecture, container_runtime, kubelet_version, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
	`, n.Name, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture, n.ContainerRuntime, n.KubeletVersion)
	done()

	if err != nil {
		exitOnCorruption(err)
		return false, fmt.Errorf("failed to insert node: %w", err)
	}

	id, _ := result.LastInsertId()
	log.Info("new node added to database", "name", n.Name, "id", id)
	db.notifyWrite()
	return true, nil
}

// UpdateNode updates an existing node in the database
func (db *DB) UpdateNode(n nodes.Node) error {
	done := db.beginWrite("update_node")
	result, err := db.conn.Exec(`
		UPDATE nodes SET
			hostname = ?,
			os_release = ?,
			kernel_version = ?,
			architecture = ?,
			container_runtime = ?,
			kubelet_version = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE name = ?
	`, n.Hostname, n.OSRelease, n.KernelVersion, n.Architecture,
		n.ContainerRuntime, n.KubeletVersion, n.Name)
	done()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to update node: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Node doesn't exist, add it (AddNode calls notifyWrite internally)
		_, err = db.AddNode(n)
		return err
	}

	db.notifyWrite()
	return nil
}

// RemoveNode removes a node and all its associated data from the database
func (db *DB) RemoveNode(name string) error {
	done := db.beginWrite("remove_node")
	defer done()
	tx, err := db.conn.Begin()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Get node ID
	var nodeID int64
	err = tx.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID)
	if err == sql.ErrNoRows {
		return nil // Node doesn't exist, nothing to do
	}
	if err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Delete node vulnerability details before vulnerabilities (details reference vulnerability IDs)
	_, err = tx.Exec(`DELETE FROM node_vulnerability_details WHERE node_vulnerability_id IN (SELECT id FROM node_vulnerabilities WHERE node_id = ?)`, nodeID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete node vulnerability details: %w", err)
	}

	// Delete node vulnerabilities
	_, err = tx.Exec(`DELETE FROM node_vulnerabilities WHERE node_id = ?`, nodeID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete node vulnerabilities: %w", err)
	}

	// Delete node package details before packages (details reference package IDs)
	_, err = tx.Exec(`DELETE FROM node_package_details WHERE node_package_id IN (SELECT id FROM node_packages WHERE node_id = ?)`, nodeID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete node package details: %w", err)
	}

	// Delete node packages
	_, err = tx.Exec(`DELETE FROM node_packages WHERE node_id = ?`, nodeID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete node packages: %w", err)
	}

	// Delete node
	_, err = tx.Exec(`DELETE FROM nodes WHERE id = ?`, nodeID)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete node: %w", err)
	}

	if err := tx.Commit(); err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info("removed node from database", "name", name, "id", nodeID)
	db.notifyWrite()
	return nil
}

// GetNode retrieves a node with its scan status
func (db *DB) GetNode(name string) (*nodes.NodeWithStatus, error) {
	var row NodeRow
	err := db.conn.QueryRow(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = nodes.id),
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = nodes.id)
		FROM nodes
		WHERE name = ?
	`, name).Scan(
		&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
		&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
		&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
		&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
		&row.PackageCount, &row.VulnerabilityCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get node: %w", err)
	}

	return db.nodeRowToNodeWithStatus(&row)
}

// GetAllNodes retrieves all nodes with their scan status
func (db *DB) GetAllNodes() ([]nodes.NodeWithStatus, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = nodes.id),
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = nodes.id)
		FROM nodes
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}

	var nodeRows []NodeRow
	for rows.Next() {
		var row NodeRow
		err := rows.Scan(
			&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
			&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
			&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
			&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
			&row.PackageCount, &row.VulnerabilityCount,
		)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		nodeRows = append(nodeRows, row)
	}
	_ = rows.Close()

	// Now convert rows to NodeWithStatus (which makes additional queries)
	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	result := make([]nodes.NodeWithStatus, 0, len(nodeRows))
	for _, row := range nodeRows {
		node, err := db.nodeRowToNodeWithStatus(&row)
		if err != nil {
			return nil, err
		}
		result = append(result, *node)
	}

	return result, nil
}

// nodeRowToNodeWithStatus converts a database row to a NodeWithStatus struct
func (db *DB) nodeRowToNodeWithStatus(row *NodeRow) (*nodes.NodeWithStatus, error) {
	node := &nodes.NodeWithStatus{
		Node: nodes.Node{
			Name: row.Name,
		},
		NodeScanStatus: nodes.NodeScanStatus{
			Status: "pending",
		},
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}

	if row.Hostname.Valid {
		node.Hostname = row.Hostname.String
	}
	if row.OSRelease.Valid {
		node.OSRelease = row.OSRelease.String
	}
	if row.KernelVersion.Valid {
		node.KernelVersion = row.KernelVersion.String
	}
	if row.Architecture.Valid {
		node.Architecture = row.Architecture.String
	}
	if row.ContainerRuntime.Valid {
		node.ContainerRuntime = row.ContainerRuntime.String
	}
	if row.KubeletVersion.Valid {
		node.KubeletVersion = row.KubeletVersion.String
	}
	if row.Status.Valid {
		node.Status = row.Status.String
	}
	if row.StatusError.Valid {
		node.StatusError = row.StatusError.String
	}
	if row.SBOMScannedAt.Valid {
		node.SBOMScannedAt = &row.SBOMScannedAt.Time
	}
	if row.VulnsScannedAt.Valid {
		node.VulnsScannedAt = &row.VulnsScannedAt.Time
	}
	if row.GrypeDBBuilt.Valid {
		t, _ := time.Parse(time.RFC3339, row.GrypeDBBuilt.String)
		node.GrypeDBBuilt = &t
	}

	node.PackageCount = row.PackageCount
	node.VulnerabilityCount = row.VulnerabilityCount

	return node, nil
}

// GetNodeScanStatus returns the scan status for a node
func (db *DB) GetNodeScanStatus(name string) (string, error) {
	var status sql.NullString
	err := db.conn.QueryRow(`
		SELECT status FROM nodes WHERE name = ?
	`, name).Scan(&status)
	if err == sql.ErrNoRows {
		return "pending", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get node scan status: %w", err)
	}
	if !status.Valid {
		return "pending", nil
	}
	return status.String, nil
}

// IsNodeScanComplete checks if a node has complete scan data
func (db *DB) IsNodeScanComplete(name string) (bool, error) {
	var nodeID int64
	var status sql.NullString
	err := db.conn.QueryRow(`
		SELECT id, status FROM nodes WHERE name = ?
	`, name).Scan(&nodeID, &status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check node scan status: %w", err)
	}

	// Must be in completed status
	if !status.Valid || status.String != StatusCompleted.String() {
		return false, nil
	}

	// Must have packages (unless it's a very minimal node)
	var pkgCount int
	err = db.conn.QueryRow(`
		SELECT COUNT(*) FROM node_packages WHERE node_id = ?
	`, nodeID).Scan(&pkgCount)
	if err != nil {
		return false, fmt.Errorf("failed to count node packages: %w", err)
	}

	return pkgCount > 0, nil
}

// GetNodeScanStatusBulk returns scan status for multiple nodes in a single query.
// Returns a map of node name -> status string. Missing nodes are returned as "pending".
func (db *DB) GetNodeScanStatusBulk(names []string) (map[string]string, error) {
	result := make(map[string]string, len(names))

	// Initialize all names as pending (for any not found in DB)
	for _, name := range names {
		result[name] = "pending"
	}

	if len(names) == 0 {
		return result, nil
	}

	// Build query with placeholders
	placeholders := make([]string, len(names))
	args := make([]interface{}, len(names))
	for i, name := range names {
		placeholders[i] = "?"
		args[i] = name
	}

	query := fmt.Sprintf(`
		SELECT name, status FROM nodes
		WHERE name IN (%s)
	`, joinStrings(placeholders, ","))

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query node statuses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name string
		var status sql.NullString
		if err := rows.Scan(&name, &status); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if status.Valid {
			result[name] = status.String
		}
		// If status is NULL, leave as "pending" (initialized above)
	}

	return result, rows.Err()
}

// IsNodeScanCompleteBulk checks scan completeness for multiple nodes in a single query.
// Returns a map of node name -> bool. Missing nodes are returned as false.
func (db *DB) IsNodeScanCompleteBulk(names []string) (map[string]bool, error) {
	result := make(map[string]bool, len(names))

	// Initialize all names as incomplete (for any not found in DB)
	for _, name := range names {
		result[name] = false
	}

	if len(names) == 0 {
		return result, nil
	}

	// Build query with placeholders
	placeholders := make([]string, len(names))
	args := make([]interface{}, len(names))
	for i, name := range names {
		placeholders[i] = "?"
		args[i] = name
	}

	// Get nodes with their status and package counts in a single query
	query := fmt.Sprintf(`
		SELECT n.name, n.status, COUNT(np.id) as pkg_count
		FROM nodes n
		LEFT JOIN node_packages np ON np.node_id = n.id
		WHERE n.name IN (%s)
		GROUP BY n.id, n.name, n.status
	`, joinStrings(placeholders, ","))

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query node scan completeness: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name string
		var status sql.NullString
		var pkgCount int
		if err := rows.Scan(&name, &status, &pkgCount); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Must be in completed status AND have packages
		result[name] = status.Valid && status.String == StatusCompleted.String() && pkgCount > 0
	}

	return result, rows.Err()
}

// UpdateNodeStatus updates the scan status for a node
func (db *DB) UpdateNodeStatus(name string, status Status, errorMsg string) error {
	done := db.beginWrite("update_node_status")
	_, err := db.conn.Exec(`
		UPDATE nodes SET
			status = ?,
			status_error = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE name = ?
	`, status.String(), errorMsg, name)
	done()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to update node status: %w", err)
	}
	db.notifyWrite()
	return nil
}

// StoreNodeSBOM stores the SBOM for a node and parses package data.
// JSON parsing is done outside the transaction to minimize write-lock hold time.
func (db *DB) StoreNodeSBOM(name string, sbomJSON []byte) error {
	// Step 1: Read node ID outside the write lock (read-only)
	var nodeID int64
	if err := db.conn.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID); err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Step 2: Parse SBOM outside the write lock (CPU-bound work, no DB writes)
	// Syft JSON format has artifacts as a top-level array.
	// Use json.RawMessage to preserve the full artifact JSON for details.
	var sbom struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Group packages by (name, version, type) to count instances and collect details
	type packageKey struct {
		Name    string
		Version string
		Type    string
	}
	type packageData struct {
		Language  string
		PURL      string
		Instances []json.RawMessage
	}
	packageGroups := make(map[packageKey]*packageData)

	for _, artifactRaw := range sbom.Artifacts {
		var pkg struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		}
		if err := json.Unmarshal(artifactRaw, &pkg); err != nil {
			log.Warn("failed to parse artifact", "error", err)
			continue
		}

		key := packageKey{Name: pkg.Name, Version: pkg.Version, Type: pkg.Type}
		if existing, ok := packageGroups[key]; ok {
			existing.Instances = append(existing.Instances, artifactRaw)
			// Keep first non-empty values for language/purl
			if existing.Language == "" && pkg.Language != "" {
				existing.Language = pkg.Language
			}
			if existing.PURL == "" && pkg.PURL != "" {
				existing.PURL = pkg.PURL
			}
		} else {
			packageGroups[key] = &packageData{
				Language:  pkg.Language,
				PURL:      pkg.PURL,
				Instances: []json.RawMessage{artifactRaw},
			}
		}
	}

	// Step 3: Compress the blob before acquiring any lock (CPU-bound, no DB).
	compressStart := time.Now()
	sbomCompressed, err := compressGzip(sbomJSON)
	if err != nil {
		return fmt.Errorf("failed to compress SBOM: %w", err)
	}
	compressMs := time.Since(compressStart).Milliseconds()

	// Step 4: Write structured package data under the write lock.
	// No blob write here — blob is written separately below.
	t0 := time.Now()
	done := db.beginWrite("store_node_sbom")

	tx, err := db.conn.Begin()
	if err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }

	// Delete existing details then packages (details reference package IDs).
	if _, err = tx.Exec(`DELETE FROM node_package_details WHERE node_package_id IN (SELECT id FROM node_packages WHERE node_id = ?)`, nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing package details: %w", err)
	}
	if _, err = tx.Exec(`DELETE FROM node_packages WHERE node_id = ?`, nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing packages: %w", err)
	}
	deleteMs := time.Since(t0).Milliseconds()

	// Batch INSERT packages (7 cols → 100 rows per batch = 700 params).
	pkgRows := make([]any, 0, len(packageGroups)*7)
	type pkgKeyOrder struct {
		key  struct {
			Name    string
			Version string
			Type    string
		}
		data *packageData
	}
	orderedPkgs := make([]pkgKeyOrder, 0, len(packageGroups))
	for k, d := range packageGroups {
		orderedPkgs = append(orderedPkgs, pkgKeyOrder{key: k, data: d})
		pkgRows = append(pkgRows, nodeID, k.Name, k.Version, k.Type, d.Language, d.PURL, len(d.Instances))
	}
	if err = batchInsert(tx,
		`INSERT INTO node_packages (node_id, name, version, type, language, purl, number_of_instances)`,
		pkgRows, 7, 100); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert packages: %w", err)
	}
	insertPkgsMs := time.Since(t0).Milliseconds() - deleteMs

	// Query back IDs to use for details inserts.
	idRows, err := tx.Query(`SELECT id, name, version, type FROM node_packages WHERE node_id = ?`, nodeID)
	if err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to query package IDs: %w", err)
	}
	pkgIDs := make(map[struct{ Name, Version, Type string }]int64)
	for idRows.Next() {
		var id int64
		var n, v, t string
		if err = idRows.Scan(&id, &n, &v, &t); err != nil {
			_ = idRows.Close()
			rollback()
			done()
			return fmt.Errorf("failed to scan package ID: %w", err)
		}
		pkgIDs[struct{ Name, Version, Type string }{n, v, t}] = id
	}
	if err = idRows.Close(); err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to close package ID rows: %w", err)
	}

	// Batch INSERT details (2 cols → 400 rows per batch = 800 params).
	detailRows := make([]any, 0, len(orderedPkgs)*2)
	for _, p := range orderedPkgs {
		pkgID, ok := pkgIDs[struct{ Name, Version, Type string }{p.key.Name, p.key.Version, p.key.Type}]
		if !ok {
			log.Warn("package ID not found after insert", "name", p.key.Name)
			continue
		}
		detailsJSON, merr := json.Marshal(p.data.Instances)
		if merr != nil {
			log.Warn("failed to marshal package details", "package", p.key.Name, "error", merr)
			detailsJSON = []byte("[]")
		}
		detailRows = append(detailRows, pkgID, string(detailsJSON))
	}
	if err = batchInsert(tx,
		`INSERT INTO node_package_details (node_package_id, details)`,
		detailRows, 2, 400); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert package details: %w", err)
	}
	insertDetailsMs := time.Since(t0).Milliseconds() - deleteMs - insertPkgsMs

	// Update node status.
	if _, err = tx.Exec(`
		UPDATE nodes SET
			status = ?,
			sbom_scanned_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StatusScanningVulnerabilities.String(), nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to update node status: %w", err)
	}

	if err = tx.Commit(); err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	done()
	structuredMs := time.Since(t0).Milliseconds()

	// Step 5: Write compressed blob in a separate write (keeps it off the hot
	// structured-data lock and limits lock hold time to a single small write).
	blobStart := time.Now()
	blobDone := db.beginWrite("store_node_sbom_blob")
	_, err = db.conn.Exec(`UPDATE nodes SET sbom_compressed = ? WHERE id = ?`, sbomCompressed, nodeID)
	blobDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to store compressed SBOM: %w", err)
	}
	blobMs := time.Since(blobStart).Milliseconds()

	log.Info("stored SBOM for node",
		"node", name,
		"unique_packages", len(packageGroups),
		"total_artifacts", len(sbom.Artifacts),
		"compress_ms", compressMs,
		"blob_compressed_kb", len(sbomCompressed)/1024,
		"delete_ms", deleteMs,
		"insert_pkgs_ms", insertPkgsMs,
		"insert_details_ms", insertDetailsMs,
		"structured_total_ms", structuredMs,
		"blob_write_ms", blobMs,
	)
	db.notifyWrite()
	return nil
}

// StoreNodeVulnerabilities stores vulnerabilities for a node.
// Groups duplicates and stores details in separate table.
// Reads and JSON parsing happen before acquiring the write lock to minimize lock hold time.
func (db *DB) StoreNodeVulnerabilities(name string, vulnJSON []byte, grypeDBBuilt time.Time) error {
	// Step 1: Read node ID outside the write lock
	var nodeID int64
	if err := db.conn.QueryRow(`SELECT id FROM nodes WHERE name = ?`, name).Scan(&nodeID); err != nil {
		return fmt.Errorf("failed to get node ID: %w", err)
	}

	// Step 2: Parse JSON and build vuln groups outside the write lock (CPU-bound).
	// Vulnerabilities are stored denormalized: package_name/version/type are written
	// inline on each row, so no packageMap lookup is needed and no match is ever
	// silently dropped due to a missing FK.
	var report struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.Unmarshal(vulnJSON, &report); err != nil {
		return fmt.Errorf("failed to parse vulnerability report: %w", err)
	}

	type parsedMatch struct {
		Vulnerability struct {
			ID   string `json:"id"`
			Severity string  `json:"severity"`
			Risk     float64 `json:"risk"`
			EPSS     []struct {
				Score      float64 `json:"epss"`
				Percentile float64 `json:"percentile"`
			} `json:"epss"`
			KnownExploited []struct {
				CVE string `json:"cve"`
			} `json:"knownExploited"`
			Fix struct {
				State    string   `json:"state"`
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	}

	type vulnKey struct {
		PackageName    string
		PackageVersion string
		PackageType    string
		CVEID          string
	}
	type vulnData struct {
		Severity       string
		Risk           float64
		EPSSScore      float64
		EPSSPercentile float64
		FixStatus      string
		FixVersion     string
		KnownExploited int
		Instances      []json.RawMessage
	}
	vulnGroups := make(map[vulnKey]*vulnData)

	for _, matchRaw := range report.Matches {
		var pm parsedMatch
		if err := json.Unmarshal(matchRaw, &pm); err != nil {
			log.Warn("failed to parse vulnerability match", "error", err)
			continue
		}

		key := vulnKey{
			PackageName:    pm.Artifact.Name,
			PackageVersion: pm.Artifact.Version,
			PackageType:    pm.Artifact.Type,
			CVEID:          pm.Vulnerability.ID,
		}

		epssScore, epssPercentile := 0.0, 0.0
		if len(pm.Vulnerability.EPSS) > 0 {
			epssScore = pm.Vulnerability.EPSS[0].Score
			epssPercentile = pm.Vulnerability.EPSS[0].Percentile
		}

		if existing, ok := vulnGroups[key]; ok {
			existing.Instances = append(existing.Instances, matchRaw)
			if pm.Vulnerability.Risk > existing.Risk {
				existing.Risk = pm.Vulnerability.Risk
			}
			if epssScore > existing.EPSSScore {
				existing.EPSSScore = epssScore
				existing.EPSSPercentile = epssPercentile
			}
			if ke := len(pm.Vulnerability.KnownExploited); ke > existing.KnownExploited {
				existing.KnownExploited = ke
			}
		} else {
			fixVersion := ""
			if len(pm.Vulnerability.Fix.Versions) > 0 {
				fixVersion = pm.Vulnerability.Fix.Versions[0]
			}
			vulnGroups[key] = &vulnData{
				Severity:       pm.Vulnerability.Severity,
				Risk:           pm.Vulnerability.Risk,
				EPSSScore:      epssScore,
				EPSSPercentile: epssPercentile,
				FixStatus:      pm.Vulnerability.Fix.State,
				FixVersion:     fixVersion,
				KnownExploited: len(pm.Vulnerability.KnownExploited),
				Instances:      []json.RawMessage{matchRaw},
			}
		}
	}

	// Step 3: Compress the blob before acquiring any lock (CPU-bound, no DB).
	compressStart := time.Now()
	vulnCompressed, err := compressGzip(vulnJSON)
	if err != nil {
		return fmt.Errorf("failed to compress vulnerability JSON: %w", err)
	}
	compressMs := time.Since(compressStart).Milliseconds()

	// Step 4: Write structured vulnerability data under the write lock.
	// No blob write here — blob is written separately below.
	t0 := time.Now()
	done := db.beginWrite("store_node_vulnerabilities")

	tx, err := db.conn.Begin()
	if err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }

	// Delete existing details then vulnerabilities (details reference vulnerability IDs).
	if _, err = tx.Exec(`DELETE FROM node_vulnerability_details WHERE node_vulnerability_id IN (SELECT id FROM node_vulnerabilities WHERE node_id = ?)`, nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing vulnerability details: %w", err)
	}
	if _, err = tx.Exec(`DELETE FROM node_vulnerabilities WHERE node_id = ?`, nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing vulnerabilities: %w", err)
	}
	deleteMs := time.Since(t0).Milliseconds()

	// Batch INSERT vulnerabilities (13 cols → 50 rows per batch = 650 params).
	type vulnRowData struct {
		key  vulnKey
		data *vulnData
	}
	orderedVulns := make([]vulnRowData, 0, len(vulnGroups))
	vulnRows := make([]any, 0, len(vulnGroups)*13)
	for k, d := range vulnGroups {
		orderedVulns = append(orderedVulns, vulnRowData{key: k, data: d})
		vulnRows = append(vulnRows,
			nodeID, k.CVEID, k.PackageName, k.PackageVersion, k.PackageType,
			d.Severity, d.Risk, d.EPSSScore, d.EPSSPercentile,
			d.FixStatus, d.FixVersion, d.KnownExploited, len(d.Instances),
		)
	}
	if err = batchInsert(tx,
		`INSERT INTO node_vulnerabilities (node_id, cve_id, package_name, package_version, package_type, severity, risk, epss_score, epss_percentile, fix_status, fix_version, known_exploited, count)`,
		vulnRows, 13, 50); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert vulnerabilities: %w", err)
	}
	insertVulnsMs := time.Since(t0).Milliseconds() - deleteMs

	// Query back IDs to use for details inserts.
	idRows, err := tx.Query(
		`SELECT id, cve_id, package_name, package_version, package_type FROM node_vulnerabilities WHERE node_id = ?`,
		nodeID)
	if err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to query vulnerability IDs: %w", err)
	}
	type vulnIDKey struct{ CVEID, PkgName, PkgVersion, PkgType string }
	vulnIDs := make(map[vulnIDKey]int64)
	for idRows.Next() {
		var id int64
		var cve, pkgName, pkgVer, pkgType string
		if err = idRows.Scan(&id, &cve, &pkgName, &pkgVer, &pkgType); err != nil {
			_ = idRows.Close()
			rollback()
			done()
			return fmt.Errorf("failed to scan vulnerability ID: %w", err)
		}
		vulnIDs[vulnIDKey{cve, pkgName, pkgVer, pkgType}] = id
	}
	if err = idRows.Close(); err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to close vulnerability ID rows: %w", err)
	}

	// Batch INSERT details (2 cols → 400 rows per batch = 800 params).
	detailRows := make([]any, 0, len(orderedVulns)*2)
	for _, v := range orderedVulns {
		vulnID, ok := vulnIDs[vulnIDKey{v.key.CVEID, v.key.PackageName, v.key.PackageVersion, v.key.PackageType}]
		if !ok {
			log.Warn("vulnerability ID not found after insert", "cve_id", v.key.CVEID)
			continue
		}
		detailsJSON, merr := json.Marshal(v.data.Instances)
		if merr != nil {
			log.Warn("failed to marshal vulnerability details", "cve_id", v.key.CVEID, "error", merr)
			detailsJSON = []byte("[]")
		}
		detailRows = append(detailRows, vulnID, string(detailsJSON))
	}
	if err = batchInsert(tx,
		`INSERT INTO node_vulnerability_details (node_vulnerability_id, details)`,
		detailRows, 2, 400); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert vulnerability details: %w", err)
	}
	insertDetailsMs := time.Since(t0).Milliseconds() - deleteMs - insertVulnsMs

	// Update node status.
	if _, err = tx.Exec(`
		UPDATE nodes SET
			status = ?,
			vulns_scanned_at = CURRENT_TIMESTAMP,
			grype_db_built = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StatusCompleted.String(), grypeDBBuilt.Format(time.RFC3339), nodeID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to update node status: %w", err)
	}

	if err = tx.Commit(); err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	done()
	structuredMs := time.Since(t0).Milliseconds()

	// Step 5: Write compressed blob in a separate write.
	blobStart := time.Now()
	blobDone := db.beginWrite("store_node_vulnerabilities_blob")
	_, err = db.conn.Exec(`UPDATE nodes SET vulnerabilities_compressed = ? WHERE id = ?`, vulnCompressed, nodeID)
	blobDone()
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to store compressed vulnerabilities: %w", err)
	}
	blobMs := time.Since(blobStart).Milliseconds()

	log.Info("stored vulnerabilities for node",
		"node", name,
		"unique", len(vulnGroups),
		"total_matches", len(report.Matches),
		"compress_ms", compressMs,
		"blob_compressed_kb", len(vulnCompressed)/1024,
		"delete_ms", deleteMs,
		"insert_vulns_ms", insertVulnsMs,
		"insert_details_ms", insertDetailsMs,
		"structured_total_ms", structuredMs,
		"blob_write_ms", blobMs,
	)
	db.notifyWrite()
	// Invalidate and rebuild the node vulnerability metrics cache. The old
	// cache continues to serve until the rebuild completes (~20s on NFS).
	go db.rebuildNodeVulnCache()
	return nil
}

// GetNodeSBOM retrieves the raw SBOM JSON for a node.
// Returns the gzip-compressed version if available, otherwise falls back to the
// uncompressed column (written by older scanner versions).
func (db *DB) GetNodeSBOM(name string) ([]byte, error) {
	var compressed []byte
	var raw sql.NullString
	err := db.conn.QueryRow(`SELECT sbom_compressed, sbom FROM nodes WHERE name = ?`, name).Scan(&compressed, &raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get node SBOM: %w", err)
	}
	if len(compressed) > 0 {
		return decompressGzip(compressed)
	}
	if raw.Valid && raw.String != "" {
		return []byte(raw.String), nil
	}
	return nil, nil
}

// GetNodeVulnerabilitiesRaw retrieves the raw vulnerability JSON for a node.
// Returns the gzip-compressed version if available, otherwise falls back to the
// uncompressed column (written by older scanner versions).
func (db *DB) GetNodeVulnerabilitiesRaw(name string) ([]byte, error) {
	var compressed []byte
	var raw sql.NullString
	err := db.conn.QueryRow(`SELECT vulnerabilities_compressed, vulnerabilities FROM nodes WHERE name = ?`, name).Scan(&compressed, &raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get node vulnerabilities: %w", err)
	}
	if len(compressed) > 0 {
		return decompressGzip(compressed)
	}
	if raw.Valid && raw.String != "" {
		return []byte(raw.String), nil
	}
	return nil, nil
}

// GetNodePackages retrieves all packages for a node with instance counts
func (db *DB) GetNodePackages(name string) ([]nodes.NodePackage, error) {
	rows, err := db.conn.Query(`
		SELECT np.id, np.node_id, np.name, np.version, np.type, np.language, np.purl,
			COALESCE(np.number_of_instances, 1) as count
		FROM node_packages np
		JOIN nodes n ON np.node_id = n.id
		WHERE n.name = ?
		ORDER BY np.name, np.version
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node packages: %w", err)
	}
	defer func() { _ = rows.Close() }()

	packages := []nodes.NodePackage{} // Initialize to empty slice, not nil (JSON: [] not null)
	for rows.Next() {
		var pkg nodes.NodePackage
		var language, purl sql.NullString
		err := rows.Scan(&pkg.ID, &pkg.NodeID, &pkg.Name, &pkg.Version, &pkg.Type, &language, &purl, &pkg.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan package row: %w", err)
		}
		if language.Valid {
			pkg.Language = language.String
		}
		if purl.Valid {
			pkg.PURL = purl.String
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetNodeVulnerabilities retrieves all vulnerabilities for a node with package info
func (db *DB) GetNodeVulnerabilities(name string) ([]nodes.NodeVulnerability, error) {
	rows, err := db.conn.Query(`
		SELECT nv.id, nv.node_id, nv.cve_id, nv.severity,
			COALESCE(nv.risk, 0) as risk,
			COALESCE(nv.epss_score, 0) as epss_score,
			COALESCE(nv.epss_percentile, 0) as epss_percentile,
			nv.fix_status, nv.fix_version, nv.known_exploited, nv.created_at,
			nv.package_name, nv.package_version, nv.package_type,
			COALESCE(nv.count, 1) as count
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		WHERE n.name = ?
		ORDER BY
			CASE nv.severity
				WHEN 'Critical' THEN 1
				WHEN 'High' THEN 2
				WHEN 'Medium' THEN 3
				WHEN 'Low' THEN 4
				WHEN 'Negligible' THEN 5
				ELSE 6
			END ASC,
			nv.cve_id ASC
	`, name)
	if err != nil {
		return nil, fmt.Errorf("failed to query node vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	vulns := []nodes.NodeVulnerability{} // Initialize to empty slice, not nil (JSON: [] not null)
	for rows.Next() {
		var vuln nodes.NodeVulnerability
		var fixStatus, fixVersion sql.NullString
		err := rows.Scan(
			&vuln.ID, &vuln.NodeID, &vuln.CVEID, &vuln.Severity,
			&vuln.Risk, &vuln.EPSSScore, &vuln.EPSSPercentile,
			&fixStatus, &fixVersion, &vuln.KnownExploited, &vuln.CreatedAt,
			&vuln.PackageName, &vuln.PackageVersion, &vuln.PackageType, &vuln.Count,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		if fixStatus.Valid {
			vuln.FixStatus = fixStatus.String
		}
		if fixVersion.Valid {
			vuln.FixVersion = fixVersion.String
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// GetNodeVulnerabilityDetails returns the JSON details for a specific node vulnerability by ID
func (db *DB) GetNodeVulnerabilityDetails(id int64) (string, error) {
	var details sql.NullString
	err := db.conn.QueryRow(`
		SELECT details FROM node_vulnerability_details WHERE node_vulnerability_id = ?
	`, id).Scan(&details)
	if err == sql.ErrNoRows {
		return "[]", nil // Return empty JSON array if no details
	}
	if err != nil {
		return "", fmt.Errorf("failed to query vulnerability details: %w", err)
	}
	if !details.Valid || details.String == "" {
		return "[]", nil // Return empty JSON array if no details
	}
	return details.String, nil
}

// GetNodePackageDetails returns the JSON details for a specific node package by ID
func (db *DB) GetNodePackageDetails(id int64) (string, error) {
	var details sql.NullString
	err := db.conn.QueryRow(`
		SELECT details FROM node_package_details WHERE node_package_id = ?
	`, id).Scan(&details)
	if err == sql.ErrNoRows {
		return "[]", nil // Return empty JSON array if no details
	}
	if err != nil {
		return "", fmt.Errorf("failed to query package details: %w", err)
	}
	if !details.Valid || details.String == "" {
		return "[]", nil // Return empty JSON array if no details
	}
	return details.String, nil
}

// NodeSummaryFilters contains filter options for node summary queries
type NodeSummaryFilters struct {
	OSNames      []string // Filter by OS release names
	VulnStatuses []string // Filter vulnerabilities by fix_status (fixed, not-fixed, wont-fix, unknown)
	PackageTypes []string // Filter vulnerabilities by package type (deb, rpm, apk, etc.)
}

// GetNodeSummaries returns vulnerability summaries for all nodes (no filtering)
func (db *DB) GetNodeSummaries() ([]nodes.NodeSummary, error) {
	return db.GetNodeSummariesFiltered(NodeSummaryFilters{})
}

// GetNodeSummariesFiltered returns vulnerability summaries for nodes with optional filtering
func (db *DB) GetNodeSummariesFiltered(filters NodeSummaryFilters) ([]nodes.NodeSummary, error) {
	// Build optional WHERE clause for the vulnerability aggregation subquery
	vulnWhere := ""
	var vulnFilterArgs []interface{}

	if len(filters.VulnStatuses) > 0 || len(filters.PackageTypes) > 0 {
		conditions := []string{}

		if len(filters.VulnStatuses) > 0 {
			placeholders := make([]string, len(filters.VulnStatuses))
			for i, status := range filters.VulnStatuses {
				placeholders[i] = "?"
				vulnFilterArgs = append(vulnFilterArgs, status)
			}
			conditions = append(conditions, "fix_status IN ("+strings.Join(placeholders, ",")+")")
		}

		if len(filters.PackageTypes) > 0 {
			placeholders := make([]string, len(filters.PackageTypes))
			for i, pkgType := range filters.PackageTypes {
				placeholders[i] = "?"
				vulnFilterArgs = append(vulnFilterArgs, pkgType)
			}
			conditions = append(conditions, "package_type IN ("+strings.Join(placeholders, ",")+")")
		}

		vulnWhere = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Build node filter clause
	nodeWhere := ""
	var nodeFilterArgs []interface{}
	if len(filters.OSNames) > 0 {
		placeholders := make([]string, len(filters.OSNames))
		for i, os := range filters.OSNames {
			placeholders[i] = "?"
			nodeFilterArgs = append(nodeFilterArgs, os)
		}
		nodeWhere = " WHERE n.os_release IN (" + strings.Join(placeholders, ",") + ")"
	}

	// Single pass over node_vulnerabilities using conditional aggregation —
	// replaces 9 correlated subqueries that each re-scanned the table per node.
	query := `
	SELECT
		n.name,
		COALESCE(n.os_release, '') as os_release,
		COALESCE(n.status, 'unknown') as status,
		COALESCE(p.package_count, 0) as package_count,
		COALESCE(v.critical, 0) as critical,
		COALESCE(v.high, 0) as high,
		COALESCE(v.medium, 0) as medium,
		COALESCE(v.low, 0) as low,
		COALESCE(v.negligible, 0) as negligible,
		COALESCE(v.unknown, 0) as unknown,
		COALESCE(v.total, 0) as total,
		COALESCE(v.unique_cves, 0) as unique_cves,
		COALESCE(v.total_risk, 0) as total_risk,
		COALESCE(v.exploit_count, 0) as exploit_count
	FROM nodes n
	LEFT JOIN (
		SELECT
			node_id,
			SUM(CASE WHEN severity = 'Critical' THEN count ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'High' THEN count ELSE 0 END) as high,
			SUM(CASE WHEN severity = 'Medium' THEN count ELSE 0 END) as medium,
			SUM(CASE WHEN severity = 'Low' THEN count ELSE 0 END) as low,
			SUM(CASE WHEN severity = 'Negligible' THEN count ELSE 0 END) as negligible,
			SUM(CASE WHEN severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible') THEN count ELSE 0 END) as unknown,
			SUM(count) as total,
			COUNT(DISTINCT cve_id) as unique_cves,
			SUM(risk * COALESCE(count, 1)) as total_risk,
			SUM(known_exploited * count) as exploit_count
		FROM node_vulnerabilities` + vulnWhere + `
		GROUP BY node_id
	) v ON v.node_id = n.id
	LEFT JOIN (
		SELECT node_id, SUM(number_of_instances) as package_count
		FROM node_packages
		GROUP BY node_id
	) p ON p.node_id = n.id` + nodeWhere + `
	ORDER BY n.name`

	args := make([]interface{}, 0, len(vulnFilterArgs)+len(nodeFilterArgs))
	args = append(args, vulnFilterArgs...)
	args = append(args, nodeFilterArgs...)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query node summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	summaries := make([]nodes.NodeSummary, 0)
	for rows.Next() {
		var summary nodes.NodeSummary
		err := rows.Scan(&summary.NodeName, &summary.OSRelease, &summary.Status, &summary.PackageCount, &summary.Critical, &summary.High,
			&summary.Medium, &summary.Low, &summary.Negligible, &summary.Unknown, &summary.Total, &summary.UniqueCVEs, &summary.TotalRisk, &summary.ExploitCount)
		if err != nil {
			return nil, fmt.Errorf("failed to scan summary row: %w", err)
		}
		// Calculate status description based on status
		summary.StatusDescription = getNodeStatusDescription(summary.Status)
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// getNodeStatusDescription returns a human-readable description for a node scan status
func getNodeStatusDescription(status string) string {
	switch status {
	case "completed":
		return "Scan complete"
	case "scanning_vulnerabilities":
		return "Scanning vulnerabilities"
	case "generating_sbom":
		return "Generating SBOM"
	case "scanning":
		return "Scanning"
	case "pending":
		return "Pending"
	case "sbom_failed":
		return "SBOM generation failed"
	case "vuln_scan_failed":
		return "Vulnerability scan failed"
	case "error":
		return "Error"
	default:
		return "Unknown"
	}
}

// GetNodeDistributionSummary returns averaged vulnerability counts grouped by OS distribution
// Only includes nodes with completed scans (status = 'completed')
func (db *DB) GetNodeDistributionSummary() ([]nodes.NodeDistributionSummary, error) {
	rows, err := db.conn.Query(`
		SELECT
			COALESCE(n.os_release, 'Unknown') as os_name,
			COUNT(DISTINCT n.id) as node_count,
			COALESCE(AVG(COALESCE(v.critical, 0)), 0) as avg_critical,
			COALESCE(AVG(COALESCE(v.high, 0)), 0) as avg_high,
			COALESCE(AVG(COALESCE(v.medium, 0)), 0) as avg_medium,
			COALESCE(AVG(COALESCE(v.low, 0)), 0) as avg_low,
			COALESCE(AVG(COALESCE(v.negligible, 0)), 0) as avg_negligible,
			COALESCE(AVG(COALESCE(v.unknown, 0)), 0) as avg_unknown,
			COALESCE(AVG(COALESCE(v.total_risk, 0)), 0) as avg_risk,
			COALESCE(AVG(COALESCE(v.exploit_count, 0)), 0) as avg_exploits,
			COALESCE(AVG(COALESCE(p.package_count, 0)), 0) as avg_packages
		FROM nodes n
		LEFT JOIN (
			SELECT
				node_id,
				SUM(CASE WHEN severity = 'Critical' THEN count ELSE 0 END) as critical,
				SUM(CASE WHEN severity = 'High' THEN count ELSE 0 END) as high,
				SUM(CASE WHEN severity = 'Medium' THEN count ELSE 0 END) as medium,
				SUM(CASE WHEN severity = 'Low' THEN count ELSE 0 END) as low,
				SUM(CASE WHEN severity = 'Negligible' THEN count ELSE 0 END) as negligible,
				SUM(CASE WHEN severity NOT IN ('Critical', 'High', 'Medium', 'Low', 'Negligible') THEN count ELSE 0 END) as unknown,
				SUM(risk * count) as total_risk,
				SUM(known_exploited * count) as exploit_count
			FROM node_vulnerabilities
			GROUP BY node_id
		) v ON v.node_id = n.id
		LEFT JOIN (
			SELECT node_id, SUM(number_of_instances) as package_count
			FROM node_packages
			GROUP BY node_id
		) p ON p.node_id = n.id
		WHERE n.status = 'completed'
		GROUP BY COALESCE(n.os_release, 'Unknown')
		ORDER BY node_count DESC, os_name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node distribution summary: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Initialize as empty slice (not nil) so JSON encodes as [] instead of null
	summaries := make([]nodes.NodeDistributionSummary, 0)
	for rows.Next() {
		var summary nodes.NodeDistributionSummary
		err := rows.Scan(&summary.OSName, &summary.NodeCount, &summary.AvgCritical, &summary.AvgHigh,
			&summary.AvgMedium, &summary.AvgLow, &summary.AvgNegligible, &summary.AvgUnknown,
			&summary.AvgRisk, &summary.AvgExploits, &summary.AvgPackages)
		if err != nil {
			return nil, fmt.Errorf("failed to scan distribution summary row: %w", err)
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// GetNodesNeedingRescan returns nodes that need to be rescanned due to grype DB update.
// Includes both 'completed' and 'vuln_scan_failed' nodes — a failed node may have
// failed precisely because of a stale or broken grype DB, and retrying with the
// fresh DB is exactly what we want. Mirrors the same fix in GetImagesNeedingRescan.
func (db *DB) GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error) {
	ts := currentGrypeDBBuilt.Format(time.RFC3339)
	rows, err := db.conn.Query(`
		SELECT id, name, hostname, os_release, kernel_version, architecture,
			container_runtime, kubelet_version, status, status_error,
			sbom_scanned_at, vulns_scanned_at, grype_db_built, created_at, updated_at,
			(SELECT COUNT(*) FROM node_packages WHERE node_id = nodes.id),
			(SELECT COUNT(*) FROM node_vulnerabilities WHERE node_id = nodes.id)
		FROM nodes
		WHERE (
			(status IN (?, ?) AND (grype_db_built IS NULL OR grype_db_built < ?))
			OR (status = 'pending' AND grype_db_built IS NOT NULL AND grype_db_built < ?)
		)
	`, StatusCompleted.String(), StatusVulnScanFailed.String(), ts, ts)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes needing rescan: %w", err)
	}

	var nodeRows []NodeRow
	for rows.Next() {
		var row NodeRow
		err := rows.Scan(
			&row.ID, &row.Name, &row.Hostname, &row.OSRelease, &row.KernelVersion,
			&row.Architecture, &row.ContainerRuntime, &row.KubeletVersion,
			&row.Status, &row.StatusError, &row.SBOMScannedAt, &row.VulnsScannedAt,
			&row.GrypeDBBuilt, &row.CreatedAt, &row.UpdatedAt,
			&row.PackageCount, &row.VulnerabilityCount,
		)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		nodeRows = append(nodeRows, row)
	}
	_ = rows.Close()

	result := make([]nodes.NodeWithStatus, 0, len(nodeRows))
	for _, row := range nodeRows {
		node, err := db.nodeRowToNodeWithStatus(&row)
		if err != nil {
			return nil, err
		}
		result = append(result, *node)
	}

	return result, nil
}

// NodeFilterOptions contains filter options for node-related pages
type NodeFilterOptions struct {
	OSNames      []string `json:"osNames"`
	VulnStatuses []string `json:"vulnStatuses"`
	PackageTypes []string `json:"packageTypes"`
}

// NodeVulnerabilityForMetrics contains vulnerability data for metrics export
// This struct combines node, package, and vulnerability data in a single row
type NodeVulnerabilityForMetrics struct {
	// Node info
	NodeName      string
	Hostname      string
	OSRelease     string
	KernelVersion string
	Architecture  string
	// Vulnerability info
	VulnID         int64
	CVEID          string
	Severity       string
	Risk           float64
	FixStatus      string
	FixVersion     string
	KnownExploited int
	// Package info
	PackageName    string
	PackageVersion string
	PackageType    string
	Count          int
}

// GetNodeVulnerabilitiesForMetrics retrieves all node vulnerabilities with full context for metrics export.
// Uses existing indexes: idx_nodes_status, idx_node_vulnerabilities_node.
func (db *DB) GetNodeVulnerabilitiesForMetrics() ([]NodeVulnerabilityForMetrics, error) {
	rows, err := db.conn.Query(`
		SELECT
			n.name,
			COALESCE(n.hostname, '') as hostname,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.kernel_version, '') as kernel_version,
			COALESCE(n.architecture, '') as architecture,
			nv.id as vuln_id,
			nv.cve_id,
			COALESCE(nv.severity, 'Unknown') as severity,
			COALESCE(nv.risk, 0) as risk,
			COALESCE(nv.fix_status, 'unknown') as fix_status,
			COALESCE(nv.fix_version, '') as fix_version,
			COALESCE(nv.known_exploited, 0) as known_exploited,
			nv.package_name,
			nv.package_version,
			COALESCE(nv.package_type, '') as package_type,
			COALESCE(nv.count, 1) as count
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		WHERE n.status = 'completed'
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node vulnerabilities for metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Pre-allocate with estimated capacity to avoid exponential reallocation on each append
	// This is critical for performance with large vulnerability datasets (can have 6000+ entries)
	result := make([]NodeVulnerabilityForMetrics, 0, 10000)
	for rows.Next() {
		var v NodeVulnerabilityForMetrics
		err := rows.Scan(
			&v.NodeName, &v.Hostname, &v.OSRelease, &v.KernelVersion, &v.Architecture,
			&v.VulnID, &v.CVEID, &v.Severity, &v.Risk, &v.FixStatus, &v.FixVersion, &v.KnownExploited,
			&v.PackageName, &v.PackageVersion, &v.PackageType, &v.Count,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan node vulnerability row: %w", err)
		}
		result = append(result, v)
	}

	return result, nil
}

// StreamNodeVulnerabilitiesForMetrics iterates over all node vulnerabilities for
// metrics. On a warm cache (populated after the first node scan completes) it
// serves entirely from memory with no DB I/O. On a cold start it falls back to
// a direct DB read and simultaneously triggers an async cache rebuild so that
// subsequent calls hit the fast path.
func (db *DB) StreamNodeVulnerabilitiesForMetrics(callback func(v NodeVulnerabilityForMetrics) error) error {
	db.cachesMu.RLock()
	cached := db.nodeVulnRows
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
	go db.rebuildNodeVulnCache()
	return trackRead("stream_node_vulnerabilities", func() error {
		return db.readNodeVulnsFromDB(callback)
	})
}

// readNodeVulnsFromDB is the raw DB read used by both the cold path of
// StreamNodeVulnerabilitiesForMetrics and rebuildNodeVulnCache.
func (db *DB) readNodeVulnsFromDB(callback func(v NodeVulnerabilityForMetrics) error) error {
	rows, err := db.conn.Query(`
		SELECT
			n.name,
			COALESCE(n.hostname, '') as hostname,
			COALESCE(n.os_release, '') as os_release,
			COALESCE(n.kernel_version, '') as kernel_version,
			COALESCE(n.architecture, '') as architecture,
			nv.id as vuln_id,
			nv.cve_id,
			COALESCE(nv.severity, 'Unknown') as severity,
			COALESCE(nv.risk, 0) as risk,
			COALESCE(nv.fix_status, 'unknown') as fix_status,
			COALESCE(nv.fix_version, '') as fix_version,
			COALESCE(nv.known_exploited, 0) as known_exploited,
			nv.package_name,
			nv.package_version,
			COALESCE(nv.package_type, '') as package_type,
			COALESCE(nv.count, 1) as count
		FROM node_vulnerabilities nv
		JOIN nodes n ON nv.node_id = n.id
		WHERE n.status = 'completed'
	`)
	if err != nil {
		return fmt.Errorf("failed to query node vulnerabilities for metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var v NodeVulnerabilityForMetrics
		if err := rows.Scan(
			&v.NodeName, &v.Hostname, &v.OSRelease, &v.KernelVersion, &v.Architecture,
			&v.VulnID, &v.CVEID, &v.Severity, &v.Risk, &v.FixStatus, &v.FixVersion, &v.KnownExploited,
			&v.PackageName, &v.PackageVersion, &v.PackageType, &v.Count,
		); err != nil {
			return fmt.Errorf("failed to scan node vulnerability row: %w", err)
		}
		if err := callback(v); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NodeScanStatusCount represents the count of nodes by scan status.
type NodeScanStatusCount struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// GetNodeScanStatusCounts returns the number of nodes grouped by scan status,
// zero-filled across every status in the scan_status table (so a status with no
// nodes still reports 0). Mirrors GetImageScanStatusCounts, but nodes are
// standalone — there is no running-container gate.
func (db *DB) GetNodeScanStatusCounts() ([]NodeScanStatusCount, error) {
	statusRows, err := db.conn.Query(`SELECT status FROM scan_status ORDER BY sort_order`)
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

	rows, err := db.conn.Query(`SELECT status, COUNT(*) FROM nodes GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("failed to query node scan status counts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count row: %w", err)
		}
		statusCounts[status] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating node status counts: %w", err)
	}

	result := make([]NodeScanStatusCount, 0, len(allStatuses))
	for _, status := range allStatuses {
		result = append(result, NodeScanStatusCount{Status: status, Count: statusCounts[status]})
	}
	return result, nil
}

// GetScannedNodes retrieves all completed nodes for the bjorn2scan_node_scanned metric
// Only selects columns needed for metrics labels to minimize overhead
func (db *DB) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	rows, err := db.conn.Query(`
		SELECT
			name,
			COALESCE(hostname, '') as hostname,
			COALESCE(os_release, '') as os_release,
			COALESCE(kernel_version, '') as kernel_version,
			COALESCE(architecture, '') as architecture
		FROM nodes
		WHERE status = 'completed'
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query scanned nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make([]nodes.NodeWithStatus, 0)
	for rows.Next() {
		var node nodes.NodeWithStatus
		err := rows.Scan(
			&node.Name, &node.Hostname, &node.OSRelease,
			&node.KernelVersion, &node.Architecture,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan node row: %w", err)
		}
		result = append(result, node)
	}

	return result, nil
}

// GetNodeFilterOptions returns distinct values for node filter dropdowns,
// serving from in-memory cache when available. The cache is invalidated on
// every write by notifyWrite().
func (db *DB) GetNodeFilterOptions() (*NodeFilterOptions, error) {
	db.cachesMu.RLock()
	cached := db.nodeFilterOpts
	db.cachesMu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	options := &NodeFilterOptions{
		OSNames:      make([]string, 0),
		VulnStatuses: make([]string, 0),
		PackageTypes: make([]string, 0),
	}

	// Get distinct OS releases from nodes
	osRows, err := db.conn.Query(`
		SELECT DISTINCT os_release FROM nodes
		WHERE os_release IS NOT NULL AND os_release != ''
		ORDER BY os_release
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query OS releases: %w", err)
	}
	for osRows.Next() {
		var osName string
		if err := osRows.Scan(&osName); err == nil && osName != "" {
			options.OSNames = append(options.OSNames, osName)
		}
	}
	_ = osRows.Close()

	// Get distinct fix statuses from node vulnerabilities
	vulnRows, err := db.conn.Query(`
		SELECT DISTINCT fix_status FROM node_vulnerabilities
		WHERE fix_status IS NOT NULL AND fix_status != ''
		ORDER BY fix_status
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query vuln statuses: %w", err)
	}
	for vulnRows.Next() {
		var status string
		if err := vulnRows.Scan(&status); err == nil && status != "" {
			options.VulnStatuses = append(options.VulnStatuses, status)
		}
	}
	_ = vulnRows.Close()

	// Get distinct package types from node packages
	pkgRows, err := db.conn.Query(`
		SELECT DISTINCT type FROM node_packages
		WHERE type IS NOT NULL AND type != ''
		ORDER BY type
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query package types: %w", err)
	}
	for pkgRows.Next() {
		var pkgType string
		if err := pkgRows.Scan(&pkgType); err == nil && pkgType != "" {
			options.PackageTypes = append(options.PackageTypes, pkgType)
		}
	}
	_ = pkgRows.Close()

	db.cachesMu.Lock()
	db.nodeFilterOpts = options
	db.cachesMu.Unlock()
	return options, nil
}
