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

// MetricsReportableStatusesSQL is the SQL tuple of scan statuses whose stored
// vulnerability rows are still worth exporting as metrics.
//
// It deliberately includes the two transient rescan states, not just
// 'completed'. A rescan moves a subject to generating_sbom and then
// scanning_vulnerabilities for up to 25 minutes (host SBOM 15m + vuln scan 10m;
// see stuckScanMaxAge). Filtering on 'completed' alone dropped every one of
// that subject's series for the whole window - about 65,400 per node on the
// kubeadm cluster - even though nothing about the node had changed and the rows
// were still sitting in the table.
//
// The rows really are still readable: StoreNodeVulnerabilities deletes and
// reinserts inside one transaction, so a concurrent reader sees the previous
// scan's data until commit. The old filter discarded data we still held.
//
// The cost of discarding it was not just a slow export. The staleness tracker
// correctly concluded the series had disappeared, marked all of them stale and
// emitted NaN, so for up to 25 minutes a day every real vulnerability on a node
// being re-verified reported as a gap rather than a value. On kubeadm that
// showed up as data_points swinging 851k -> 729k -> 876k and staleness_ms
// reaching 122,591 against a median of 3.
//
// Failure states (sbom_failed, sbom_unavailable, vuln_scan_failed) and pending
// stay excluded, preserving existing behaviour: a subject that never completed
// has no rows to report anyway, and one whose scan failed should not keep
// publishing older findings as if current.
//
// This is a raw SQL fragment rather than a parameter list because it is
// interpolated into queries that take no other arguments; the values are
// compile-time constants from this file, never user input.
const MetricsReportableStatusesSQL = `('completed', 'generating_sbom', 'scanning_vulnerabilities')`
