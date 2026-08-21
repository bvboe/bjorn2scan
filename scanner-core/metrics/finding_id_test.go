package metrics

import (
	"strings"
	"testing"

	"github.com/bvboe/bjorn2scan/scanner-core/database"
)

// TestFindingIDSurvivesRescan is the whole point of the change.
//
// A rescan deletes every vulnerability row for an entity and re-inserts it, so
// VulnID changes even though the finding did not. While vulnerability_id was
// derived from that row id, every series in the deployment was retired and
// recreated on each grype database update — measured in kind as all 2,725 node
// findings moving from ids 546–3,270 to 3,271–5,995, with 100% of the retired
// series having a live twin identical in every other label.
func TestFindingIDSurvivesRescan(t *testing.T) {
	const uuid = "4313e158-9077-4b70-aea7-9d3130552362"

	before := database.NodeVulnerabilityForMetrics{
		VulnID: 210, NodeName: "kind-control-plane", Hostname: "kind-control-plane",
		OSRelease: "Debian GNU/Linux 13 (trixie)", CVEID: "CVE-2026-7383",
		PackageName: "openssl", PackageVersion: "3.5.6-1~deb13u1", PackageType: "deb",
		Severity: "High", FixStatus: "fixed", FixVersion: "3.5.6-1~deb13u2",
	}
	// Same finding after a rescan: only the row id moved.
	after := before
	after.VulnID = 4910

	got := buildNodeVulnerabilityLabels(uuid, "Kind Cluster", before)["vulnerability_id"]
	want := buildNodeVulnerabilityLabels(uuid, "Kind Cluster", after)["vulnerability_id"]

	if got != want {
		t.Errorf("vulnerability_id changed across a rescan: %q then %q\n"+
			"every series in the deployment would churn on each grype update", got, want)
	}
}

// TestContainerFindingIDSurvivesRescan is the image-side equivalent.
func TestContainerFindingIDSurvivesRescan(t *testing.T) {
	const uuid = "abc-123"

	before := database.ContainerVulnerability{
		VulnID: 17, Namespace: "default", Pod: "web-1", Name: "nginx",
		NodeName: "node-1", Reference: "nginx:1.25", Digest: "sha256:deadbeef",
		OSName: "debian", CVEID: "CVE-2024-1234", PackageName: "openssl",
		PackageVersion: "3.0.0", Severity: "Critical", FixStatus: "fixed",
		FixedVersion: "3.0.13",
	}
	after := before
	after.VulnID = 24087

	got := buildContainerVulnerabilityLabels(uuid, "prod", before)["vulnerability_id"]
	want := buildContainerVulnerabilityLabels(uuid, "prod", after)["vulnerability_id"]

	if got != want {
		t.Errorf("vulnerability_id changed across a rescan: %q then %q", got, want)
	}
}

// TestContainerFindingIDIsPerImageNotPerContainer pins the grain.
//
// The id it replaces came from image_vulnerabilities.id, which is shared by every
// container running the image. Hashing the container identity in as well would
// look harmless but would silently inflate any "count distinct findings" query by
// the replica count.
func TestContainerFindingIDIsPerImageNotPerContainer(t *testing.T) {
	const uuid = "abc-123"

	base := database.ContainerVulnerability{
		Digest: "sha256:deadbeef", CVEID: "CVE-2024-1234",
		PackageName: "openssl", PackageVersion: "3.0.0",
		Namespace: "default", Pod: "web-1", Name: "nginx", NodeName: "node-1",
	}
	// Same image finding, observed in a different pod on a different node.
	other := base
	other.Pod = "web-2"
	other.Name = "nginx-sidecar"
	other.NodeName = "node-2"
	other.Namespace = "staging"

	a := buildContainerVulnerabilityLabels(uuid, "prod", base)["vulnerability_id"]
	b := buildContainerVulnerabilityLabels(uuid, "prod", other)["vulnerability_id"]

	if a != b {
		t.Errorf("same image finding produced different ids across containers (%q vs %q); "+
			"counting distinct vulnerability_id would over-report findings by the replica count", a, b)
	}
}

// TestFindingIDDistinguishesFindings checks the other direction: the id must not
// collapse findings that are genuinely different. Each case varies exactly one
// component of the identity tuple.
func TestFindingIDDistinguishesFindings(t *testing.T) {
	const uuid = "abc-123"
	base := database.NodeVulnerabilityForMetrics{
		NodeName: "node-1", CVEID: "CVE-2024-1234",
		PackageName: "openssl", PackageVersion: "3.0.0", PackageType: "deb",
	}
	baseID := buildNodeVulnerabilityLabels(uuid, "prod", base)["vulnerability_id"]

	tests := []struct {
		name   string
		mutate func(*database.NodeVulnerabilityForMetrics)
	}{
		{"different node", func(v *database.NodeVulnerabilityForMetrics) { v.NodeName = "node-2" }},
		{"different CVE", func(v *database.NodeVulnerabilityForMetrics) { v.CVEID = "CVE-2024-9999" }},
		{"different package", func(v *database.NodeVulnerabilityForMetrics) { v.PackageName = "libssl" }},
		{"different version", func(v *database.NodeVulnerabilityForMetrics) { v.PackageVersion = "3.0.1" }},
		{"different type", func(v *database.NodeVulnerabilityForMetrics) { v.PackageType = "rpm" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := base
			tt.mutate(&v)
			if got := buildNodeVulnerabilityLabels(uuid, "prod", v)["vulnerability_id"]; got == baseID {
				t.Errorf("%s produced the same id %q; distinct findings would be merged", tt.name, got)
			}
		})
	}
}

// TestFindingIDFieldBoundaries guards the separator. Without one, ("ab","c") and
// ("a","bc") hash identically, so a package named "openssl" at version "1.0"
// could collide with "openss" at "l1.0".
func TestFindingIDFieldBoundaries(t *testing.T) {
	a := findingID("uuid", "ab", "c")
	b := findingID("uuid", "a", "bc")
	if a == b {
		t.Errorf("field boundaries are not encoded: %q == %q", a, b)
	}
}

// TestFindingIDIsDeploymentScoped keeps the uuid prefix. Two deployments can
// legitimately hold the same finding, and their ids must not collide when both
// push to the same backend.
func TestFindingIDIsDeploymentScoped(t *testing.T) {
	a := findingID("uuid-one", "node-1", "CVE-2024-1234", "openssl", "3.0.0", "deb")
	b := findingID("uuid-two", "node-1", "CVE-2024-1234", "openssl", "3.0.0", "deb")

	if a == b {
		t.Fatal("ids collide across deployments")
	}
	if !strings.HasPrefix(a, "uuid-one.") {
		t.Errorf("id %q should remain visibly scoped to its deployment", a)
	}
}

// TestFindingIDIsDeterministicAcrossProcesses fails if the hash is ever swapped
// for something seeded per-process (Go's maphash, for instance). Agents and
// scan-servers restart independently; a per-process seed would make every restart
// look like a fleet-wide rescan.
func TestFindingIDIsDeterministicAcrossProcesses(t *testing.T) {
	const want = "uuid.22c5bb5697af34d5"
	got := findingID("uuid", "node-1", "CVE-2024-1234", "openssl", "3.0.0", "deb")
	if got != want {
		t.Errorf("findingID = %q, want %q\n"+
			"if this changed deliberately, every existing series is renamed once on rollout; "+
			"if it changed because the hash is seeded per-process, restarts will churn every series",
			got, want)
	}
}
