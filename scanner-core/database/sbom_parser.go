package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// SyftPackage represents a package from Syft SBOM
// We store the complete raw JSON to preserve ALL fields (current and future) and original field order
type SyftPackage struct {
	Name    string          `json:"-"` // Extracted for indexing, not marshaled
	Version string          `json:"-"` // Extracted for indexing, not marshaled
	Type    string          `json:"-"` // Extracted for indexing, not marshaled
	Raw     json.RawMessage `json:"-"` // Complete raw JSON with original field order
}

// UnmarshalJSON implements custom unmarshaling to extract index fields and preserve raw JSON
func (p *SyftPackage) UnmarshalJSON(data []byte) error {
	// Store the complete raw JSON (preserves all fields and original order)
	p.Raw = json.RawMessage(data)

	// Extract only the fields we need for indexing (name/version/type)
	var temp struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	p.Name = temp.Name
	p.Version = temp.Version
	p.Type = temp.Type
	return nil
}

// MarshalJSON returns the raw JSON (preserving all fields and original order)
// Uses value receiver so it works when marshaling []SyftPackage (not just []*SyftPackage)
func (p SyftPackage) MarshalJSON() ([]byte, error) {
	return p.Raw, nil
}

// SyftImageMetadata represents the image metadata from Syft SBOM
type SyftImageMetadata struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// SyftSource represents the source metadata from Syft SBOM
type SyftSource struct {
	Type     string            `json:"type"`
	Metadata SyftImageMetadata `json:"metadata"`
}

// SyftSBOM represents a Syft SBOM document
type SyftSBOM struct {
	Artifacts []SyftPackage `json:"artifacts"`
	Source    SyftSource    `json:"source"`
}

// GrypeMatch represents a vulnerability match from Grype
// We store the complete raw JSON to preserve ALL fields (current and future) and original field order
type GrypeMatch struct {
	// Fields extracted for indexing (not marshaled back)
	Vulnerability GrypeVulnerability `json:"-"`
	Artifact      GrypeArtifact      `json:"-"`

	// Complete raw JSON with original field order
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON implements custom unmarshaling to extract index fields and preserve raw JSON
func (m *GrypeMatch) UnmarshalJSON(data []byte) error {
	// Store the complete raw JSON (preserves all fields and original order)
	m.Raw = json.RawMessage(data)

	// Extract only the fields we need for indexing
	var temp struct {
		Vulnerability GrypeVulnerability `json:"vulnerability"`
		Artifact      GrypeArtifact      `json:"artifact"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	m.Vulnerability = temp.Vulnerability
	m.Artifact = temp.Artifact
	return nil
}

// MarshalJSON returns the raw JSON (preserving all fields and original order)
// Uses value receiver so it works when marshaling []GrypeMatch (not just []*GrypeMatch)
func (m GrypeMatch) MarshalJSON() ([]byte, error) {
	return m.Raw, nil
}

// GrypeArtifact represents the artifact (package) that has a vulnerability
type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GrypeVulnerability represents vulnerability details
type GrypeVulnerability struct {
	ID             string              `json:"id"`
	Severity       string              `json:"severity"`
	Fix            GrypeFix            `json:"fix"`
	Risk           float64             `json:"risk"`
	EPSS           []GrypeEPSS         `json:"epss"`
	KnownExploited []GrypeKnownExploit `json:"knownExploited"`
}

// GrypeEPSS represents EPSS (Exploit Prediction Scoring System) data
type GrypeEPSS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// GrypeKnownExploit represents known exploit information from CISA KEV
type GrypeKnownExploit struct {
	CVE                        string   `json:"cve"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	DateAdded                  string   `json:"dateAdded"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	URLs                       []string `json:"urls"`
	CWEs                       []string `json:"cwes"`
}

// GrypeRelatedVuln represents related vulnerabilities
type GrypeRelatedVuln struct {
	ID string `json:"id"`
}

// GrypeFix represents fix information
type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

// GrypeMatchDetail represents match details
type GrypeMatchDetail struct {
	Type       string          `json:"type"`
	Found      GrypeFound      `json:"found"`
	SearchedBy GrypeSearchedBy `json:"searchedBy"`
}

// GrypeFound represents what was found
type GrypeFound struct {
	VersionConstraint string `json:"versionConstraint"`
}

// GrypeSearchedBy represents search criteria
type GrypeSearchedBy struct {
	Package GrypePackageInfo `json:"package"`
}

// GrypePackageInfo represents package information
type GrypePackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GrypeDistro represents distribution information from Grype
type GrypeDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// GrypeDocument represents a Grype vulnerability scan document
type GrypeDocument struct {
	Matches []GrypeMatch `json:"matches"`
	Distro  *GrypeDistro `json:"distro"`
}

// parseSBOMData parses SBOM JSON and populates packages table
func parseSBOMData(db *DB, imageID int64, sbomJSON []byte) error {
	var sbom SyftSBOM
	if err := json.Unmarshal(sbomJSON, &sbom); err != nil {
		return fmt.Errorf("failed to unmarshal SBOM: %w", err)
	}

	// Count packages by name+version+type
	packageCounts := make(map[string]int)
	packageInfo := make(map[string][]SyftPackage) // Changed to store ALL packages, not just first

	for _, pkg := range sbom.Artifacts {
		key := fmt.Sprintf("%s|%s|%s", pkg.Name, pkg.Version, pkg.Type)
		packageCounts[key]++
		// Store ALL complete package data for this key
		packageInfo[key] = append(packageInfo[key], pkg)
	}

	// Write under the write lock.
	done := db.beginWrite("store_image_packages")

	tx, err := db.conn.Begin()
	if err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }

	// Delete existing details then packages to allow clean batch inserts.
	if _, err = tx.Exec(`DELETE FROM image_package_details WHERE package_id IN (SELECT id FROM image_packages WHERE image_id = ?)`, imageID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing image package details: %w", err)
	}
	if _, err = tx.Exec(`DELETE FROM image_packages WHERE image_id = ?`, imageID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing image packages: %w", err)
	}

	// Collect ordered package list for deterministic details inserts.
	type pkgEntry struct {
		name, version, pkgType string
		count                  int
		packages               []SyftPackage
	}
	entries := make([]pkgEntry, 0, len(packageCounts))
	pkgRows := make([]any, 0, len(packageCounts)*5)
	for key, count := range packageCounts {
		pkgs := packageInfo[key]
		if len(pkgs) == 0 {
			continue
		}
		p := pkgs[0]
		entries = append(entries, pkgEntry{p.Name, p.Version, p.Type, count, pkgs})
		pkgRows = append(pkgRows, imageID, p.Name, p.Version, p.Type, count)
	}

	// Batch INSERT packages (5 cols → 150 rows per batch = 750 params).
	if err = batchInsert(tx,
		`INSERT INTO image_packages (image_id, name, version, type, number_of_instances)`,
		pkgRows, 5, 150); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert image packages: %w", err)
	}

	// Query back IDs for details inserts.
	idRows, err := tx.Query(`SELECT id, name, version, type FROM image_packages WHERE image_id = ?`, imageID)
	if err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to query image package IDs: %w", err)
	}
	pkgIDs := make(map[string]int64) // "name|version|type" → id
	for idRows.Next() {
		var id int64
		var n, v, t string
		if err = idRows.Scan(&id, &n, &v, &t); err != nil {
			_ = idRows.Close()
			rollback()
			done()
			return fmt.Errorf("failed to scan image package ID: %w", err)
		}
		pkgIDs[n+"|"+v+"|"+t] = id
	}
	if err = idRows.Close(); err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to close image package ID rows: %w", err)
	}

	// Batch INSERT details (2 cols → 400 rows per batch = 800 params).
	detailRows := make([]any, 0, len(entries)*2)
	for _, e := range entries {
		pkgID, ok := pkgIDs[e.name+"|"+e.version+"|"+e.pkgType]
		if !ok {
			log.Warn("image package ID not found after insert", "name", e.name)
			continue
		}
		detailsJSON, merr := json.Marshal(e.packages)
		if merr != nil {
			log.Warn("failed to marshal image package details", "name", e.name, "error", merr)
			continue
		}
		detailRows = append(detailRows, pkgID, string(detailsJSON))
	}
	if err = batchInsert(tx,
		`INSERT INTO image_package_details (package_id, details)`,
		detailRows, 2, 400); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert image package details: %w", err)
	}

	// Update architecture if available.
	if sbom.Source.Metadata.Architecture != "" {
		if _, err = tx.Exec(`UPDATE images SET architecture = ? WHERE id = ?`,
			sbom.Source.Metadata.Architecture, imageID); err != nil {
			exitOnCorruption(err)
			log.Warn("failed to update images with architecture info", "error", err)
		}
	}

	if err = tx.Commit(); err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	done()

	log.Info("parsed SBOM",
		"image_id", imageID, "unique_packages", len(entries), "total_instances", len(sbom.Artifacts))
	return nil
}

// parseVulnerabilityData parses Grype vulnerability JSON and populates vulnerabilities table
func parseVulnerabilityData(db *DB, imageID int64, vulnJSON []byte) error {
	var doc GrypeDocument
	if err := json.Unmarshal(vulnJSON, &doc); err != nil {
		return fmt.Errorf("failed to unmarshal vulnerability data: %w", err)
	}

	// Group vulnerabilities by unique key
	type vulnKey struct {
		cveID          string
		packageName    string
		packageVersion string
		packageType    string
	}
	vulnCounts := make(map[vulnKey]int)
	vulnInfo := make(map[vulnKey][]GrypeMatch) // Changed to store ALL matches, not just first

	for _, match := range doc.Matches {
		// Get package info from artifact field
		key := vulnKey{
			cveID:          match.Vulnerability.ID,
			packageName:    match.Artifact.Name,
			packageVersion: match.Artifact.Version,
			packageType:    match.Artifact.Type,
		}

		vulnCounts[key]++
		// Store ALL matches for this vulnerability, not just the first one
		vulnInfo[key] = append(vulnInfo[key], match)
	}

	// Write under the write lock.
	done := db.beginWrite("store_image_vulnerabilities")

	tx, err := db.conn.Begin()
	if err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	rollback := func() { _ = tx.Rollback() }

	// Delete existing details then vulnerabilities to allow clean batch inserts.
	if _, err = tx.Exec(`DELETE FROM image_vulnerability_details WHERE vulnerability_id IN (SELECT id FROM image_vulnerabilities WHERE image_id = ?)`, imageID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing image vulnerability details: %w", err)
	}
	if _, err = tx.Exec(`DELETE FROM image_vulnerabilities WHERE image_id = ?`, imageID); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to delete existing image vulnerabilities: %w", err)
	}

	// Collect ordered vuln list for deterministic details inserts.
	type vulnEntry struct {
		key     vulnKey
		matches []GrypeMatch
		// summary fields
		severity, fixStatus, fixedVersion string
		count                             int
		risk, epssScore, epssPercentile   float64
		knownExploited                    int
	}
	entries := make([]vulnEntry, 0, len(vulnCounts))
	vulnRows := make([]any, 0, len(vulnCounts)*13)
	for key, count := range vulnCounts {
		matches := vulnInfo[key]
		if len(matches) == 0 {
			log.Warn("no matches found for vulnerability", "cve_id", key.cveID)
			continue
		}
		m := matches[0]
		fixStatus := m.Vulnerability.Fix.State
		if fixStatus == "" {
			if len(m.Vulnerability.Fix.Versions) > 0 {
				fixStatus = "fixed"
			} else {
				fixStatus = "not-fixed"
			}
		}
		fixedVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = m.Vulnerability.Fix.Versions[0]
		}
		epssScore, epssPercentile := 0.0, 0.0
		if len(m.Vulnerability.EPSS) > 0 {
			epssScore = m.Vulnerability.EPSS[0].Score
			epssPercentile = m.Vulnerability.EPSS[0].Percentile
		}
		knownExploited := len(m.Vulnerability.KnownExploited)

		entries = append(entries, vulnEntry{key, matches, m.Vulnerability.Severity, fixStatus, fixedVersion, count, m.Vulnerability.Risk, epssScore, epssPercentile, knownExploited})
		vulnRows = append(vulnRows,
			imageID, key.cveID, key.packageName, key.packageVersion, key.packageType,
			m.Vulnerability.Severity, fixStatus, fixedVersion, count,
			m.Vulnerability.Risk, epssScore, epssPercentile, knownExploited,
		)
	}

	// Batch INSERT vulnerabilities (13 cols → 50 rows per batch = 650 params).
	if err = batchInsert(tx,
		`INSERT INTO image_vulnerabilities (image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count, risk, epss_score, epss_percentile, known_exploited)`,
		vulnRows, 13, 50); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert image vulnerabilities: %w", err)
	}

	// Query back IDs for details inserts.
	idRows, err := tx.Query(`SELECT id, cve_id, package_name, package_version, package_type FROM image_vulnerabilities WHERE image_id = ?`, imageID)
	if err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to query image vulnerability IDs: %w", err)
	}
	vulnIDs := make(map[string]int64) // "cve|name|ver|type" → id
	for idRows.Next() {
		var id int64
		var cve, pname, pver, ptype string
		if err = idRows.Scan(&id, &cve, &pname, &pver, &ptype); err != nil {
			_ = idRows.Close()
			rollback()
			done()
			return fmt.Errorf("failed to scan image vulnerability ID: %w", err)
		}
		vulnIDs[cve+"|"+pname+"|"+pver+"|"+ptype] = id
	}
	if err = idRows.Close(); err != nil {
		rollback()
		done()
		return fmt.Errorf("failed to close image vulnerability ID rows: %w", err)
	}

	// Batch INSERT details (2 cols → 400 rows per batch = 800 params).
	detailRows := make([]any, 0, len(entries)*2)
	for _, e := range entries {
		k := e.key.cveID + "|" + e.key.packageName + "|" + e.key.packageVersion + "|" + e.key.packageType
		vulnID, ok := vulnIDs[k]
		if !ok {
			log.Warn("image vulnerability ID not found after insert", "cve_id", e.key.cveID)
			continue
		}
		detailsJSON, merr := json.Marshal(e.matches)
		if merr != nil {
			log.Warn("failed to marshal image vulnerability details", "cve_id", e.key.cveID, "error", merr)
			continue
		}
		detailRows = append(detailRows, vulnID, string(detailsJSON))
	}
	if err = batchInsert(tx,
		`INSERT INTO image_vulnerability_details (vulnerability_id, details)`,
		detailRows, 2, 400); err != nil {
		rollback()
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to batch insert image vulnerability details: %w", err)
	}

	// Update distro info if available.
	if doc.Distro != nil {
		if _, err = tx.Exec(`UPDATE images SET os_name = ?, os_version = ? WHERE id = ?`,
			doc.Distro.Name, doc.Distro.Version, imageID); err != nil {
			exitOnCorruption(err)
			log.Warn("failed to update images with distro info", "error", err)
		}
	}

	if err = tx.Commit(); err != nil {
		done()
		exitOnCorruption(err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	done()

	// Invalidate and rebuild the container vulnerability metrics cache. The old
	// cache continues to serve until the rebuild completes.
	go db.rebuildContainerVulnCache()

	log.Info("parsed vulnerabilities",
		"image_id", imageID, "unique_vulnerabilities", len(entries))
	return nil
}

// ParseAndStoreImageData parses both SBOM and vulnerability data for an image
// This should be called whenever SBOM or vulnerability data is stored
func (db *DB) ParseAndStoreImageData(imageID int64) error {
	var sbomCompressed, vulnCompressed []byte
	var sbomRaw, vulnRaw sql.NullString
	err := db.conn.QueryRow(`
		SELECT sbom_compressed, sbom, vulnerabilities_compressed, vulnerabilities
		FROM images WHERE id = ?
	`, imageID).Scan(&sbomCompressed, &sbomRaw, &vulnCompressed, &vulnRaw)
	if err != nil {
		return fmt.Errorf("failed to query image data: %w", err)
	}

	// Resolve SBOM bytes: compressed wins over raw.
	var sbomBytes []byte
	if len(sbomCompressed) > 0 {
		if sbomBytes, err = decompressGzip(sbomCompressed); err != nil {
			return fmt.Errorf("failed to decompress SBOM: %w", err)
		}
	} else if sbomRaw.Valid && sbomRaw.String != "" {
		sbomBytes = []byte(sbomRaw.String)
	}
	if sbomBytes != nil {
		if err = parseSBOMData(db, imageID, sbomBytes); err != nil {
			return fmt.Errorf("failed to parse SBOM: %w", err)
		}
	}

	// Resolve vulnerability bytes: compressed wins over raw.
	var vulnBytes []byte
	if len(vulnCompressed) > 0 {
		if vulnBytes, err = decompressGzip(vulnCompressed); err != nil {
			return fmt.Errorf("failed to decompress vulnerabilities: %w", err)
		}
	} else if vulnRaw.Valid && vulnRaw.String != "" {
		vulnBytes = []byte(vulnRaw.String)
	}
	if vulnBytes != nil {
		if err = parseVulnerabilityData(db, imageID, vulnBytes); err != nil {
			return fmt.Errorf("failed to parse vulnerabilities: %w", err)
		}
	}

	return nil
}
