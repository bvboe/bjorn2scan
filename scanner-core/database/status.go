package database

// Status represents the unified scan status for an image
// combining both SBOM generation and vulnerability scanning stages
type Status string

const (
	// StatusPending indicates the image has not been scanned yet
	StatusPending Status = "pending"

	// StatusGeneratingSBOM indicates SBOM generation is in progress
	StatusGeneratingSBOM Status = "generating_sbom"

	// StatusSBOMFailed indicates SBOM generation failed due to an error
	StatusSBOMFailed Status = "sbom_failed"

	// StatusSBOMUnavailable indicates SBOM cannot be generated (no scanner on node)
	StatusSBOMUnavailable Status = "sbom_unavailable"

	// StatusScanningVulnerabilities indicates SBOM is complete and vulnerability scanning is in progress
	StatusScanningVulnerabilities Status = "scanning_vulnerabilities"

	// StatusVulnScanFailed indicates vulnerability scanning failed (SBOM exists)
	StatusVulnScanFailed Status = "vuln_scan_failed"

	// StatusCompleted indicates both SBOM generation and vulnerability scanning completed successfully
	StatusCompleted Status = "completed"
)

// String returns the string representation of the status
func (s Status) String() string {
	return string(s)
}

// IsTerminal returns true if the status is terminal (no further processing needed)
func (s Status) IsTerminal() bool {
	switch s {
	case StatusSBOMFailed, StatusSBOMUnavailable, StatusVulnScanFailed, StatusCompleted:
		return true
	default:
		return false
	}
}

// IsError returns true if the status represents an error condition
func (s Status) IsError() bool {
	switch s {
	case StatusSBOMFailed, StatusVulnScanFailed:
		return true
	default:
		return false
	}
}

// HasSBOM returns true if the status indicates SBOM data should be available
func (s Status) HasSBOM() bool {
	switch s {
	case StatusScanningVulnerabilities, StatusVulnScanFailed, StatusCompleted:
		return true
	default:
		return false
	}
}

// HasVulnerabilities returns true if vulnerability data should be available
func (s Status) HasVulnerabilities() bool {
	return s == StatusCompleted
}
