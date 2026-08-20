package controller

import (
	"testing"

	chart "helm.sh/helm/v4/pkg/chart/v2"
	relcommon "helm.sh/helm/v4/pkg/release/common"
	release "helm.sh/helm/v4/pkg/release/v1"
)

func rev(revision int, version string, status relcommon.Status) *release.Release {
	return &release.Release{
		Name:    "bjorn2scan",
		Version: revision,
		Info:    &release.Info{Status: status},
		Chart: &chart.Chart{
			Metadata: &chart.Metadata{Name: "bjorn2scan", Version: version},
		},
	}
}

// TestLastDeployedFrom covers the selection that keeps a failed upgrade from
// masquerading as the current state.
//
// The production incident: revision 4 failed while trying to reach 2.0.12, and
// the controller read 2.0.12 back as "current". Because that matched the
// registry's latest, every subsequent hourly run reported "up to date" and exited
// 0 while the cluster sat on 2.0.11 — one failure became permanent silence.
func TestLastDeployedFrom(t *testing.T) {
	tests := []struct {
		name        string
		history     []*release.Release
		wantVersion string
		wantRev     int
		wantOK      bool
	}{
		{
			name: "failed revision above a deployed one is ignored",
			history: []*release.Release{
				rev(3, "2.0.11", relcommon.StatusSuperseded),
				rev(4, "2.0.12", relcommon.StatusFailed),
			},
			wantVersion: "", wantRev: 0, wantOK: false,
		},
		{
			name: "the actual production shape: deployed, then two failed upgrades",
			history: []*release.Release{
				rev(3, "2.0.11", relcommon.StatusDeployed),
				rev(4, "2.0.12", relcommon.StatusFailed),
				rev(5, "2.0.13", relcommon.StatusFailed),
			},
			wantVersion: "2.0.11", wantRev: 3, wantOK: true,
		},
		{
			name: "highest deployed wins regardless of slice order",
			history: []*release.Release{
				rev(5, "2.0.13", relcommon.StatusFailed),
				rev(2, "2.0.10", relcommon.StatusDeployed),
				rev(4, "2.0.12", relcommon.StatusDeployed),
				rev(1, "2.0.9", relcommon.StatusDeployed),
			},
			wantVersion: "2.0.12", wantRev: 4, wantOK: true,
		},
		{
			name:        "no history at all",
			history:     nil,
			wantVersion: "", wantRev: 0, wantOK: false,
		},
		{
			name: "nothing ever deployed",
			history: []*release.Release{
				rev(1, "2.0.11", relcommon.StatusFailed),
				rev(2, "2.0.12", relcommon.StatusPendingUpgrade),
			},
			wantVersion: "", wantRev: 0, wantOK: false,
		},
		{
			name: "malformed entries are skipped, not fatal",
			history: []*release.Release{
				nil,
				{Name: "no-info", Version: 9},
				{Name: "no-chart", Version: 8, Info: &release.Info{Status: relcommon.StatusDeployed}},
				rev(2, "2.0.10", relcommon.StatusDeployed),
			},
			wantVersion: "2.0.10", wantRev: 2, wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, revision, ok := lastDeployedFrom(tt.history)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if revision != tt.wantRev {
				t.Errorf("revision = %d, want %d", revision, tt.wantRev)
			}
		})
	}
}
