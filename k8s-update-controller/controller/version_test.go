package controller

import (
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/k8s-update-controller/config"
)

func TestShouldUpdate(t *testing.T) {
	tests := []struct {
		name        string
		constraints *config.VersionConstraints
		current     string
		candidate   string
		wantUpdate  bool
		reason      string
	}{
		{
			name: "Same version - no update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "0.1.34",
			wantUpdate: false,
			reason:     "candidate version is not newer",
		},
		{
			name: "Older version - no update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.35",
			candidate:  "0.1.34",
			wantUpdate: false,
			reason:     "candidate version is not newer",
		},
		{
			name: "Patch update - should update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "0.1.35",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Minor update allowed - should update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "0.2.0",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Minor update disallowed - no update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: false,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "0.2.0",
			wantUpdate: false,
			reason:     "minor version update (0.1 → 0.2) not allowed",
		},
		{
			name: "Major update allowed - should update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: true,
			},
			current:    "0.9.9",
			candidate:  "1.0.0",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Major update disallowed - no update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.9.9",
			candidate:  "1.0.0",
			wantUpdate: false,
			reason:     "major version update (0 → 1) not allowed",
		},
		{
			name: "Pinned version - exact match - no update",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				PinnedVersion:   "0.1.34",
			},
			current:    "0.1.34",
			candidate:  "0.1.35",
			wantUpdate: false,
			reason:     "pinned to version 0.1.34",
		},
		{
			name: "Pinned version - need upgrade",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				PinnedVersion:   "0.1.35",
			},
			current:    "0.1.34",
			candidate:  "0.1.35",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Pinned version - wrong candidate",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				PinnedVersion:   "0.1.35",
			},
			current:    "0.1.34",
			candidate:  "0.1.36",
			wantUpdate: false,
			reason:     "pinned to version 0.1.35",
		},
		{
			name: "Min version constraint - allowed",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				MinVersion:      "0.1.30",
			},
			current:    "0.1.34",
			candidate:  "0.1.35",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Min version constraint - blocks downgrade",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				MinVersion:      "0.1.34",
			},
			current:    "0.1.35",
			candidate:  "0.1.33",
			wantUpdate: false,
			reason:     "candidate version is not newer",
		},
		{
			name: "Max version constraint - allowed",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				MaxVersion:      "0.2.0",
			},
			current:    "0.1.34",
			candidate:  "0.1.35",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Max version constraint - blocks upgrade",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				MaxVersion:      "0.1.35",
			},
			current:    "0.1.34",
			candidate:  "0.1.36",
			wantUpdate: false,
			reason:     "candidate above maximum version 0.1.35",
		},
		{
			name: "Complex constraint - pinned takes precedence",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				PinnedVersion:   "0.1.35",
				MinVersion:      "0.1.30",
				MaxVersion:      "0.2.0",
			},
			current:    "0.1.34",
			candidate:  "0.1.36",
			wantUpdate: false,
			reason:     "pinned to version 0.1.35",
		},
		{
			name: "Complex constraint - min/max range",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
				MinVersion:      "0.1.30",
				MaxVersion:      "0.2.0",
			},
			current:    "0.1.34",
			candidate:  "0.1.50",
			wantUpdate: true,
			reason:     "",
		},
		{
			name: "Invalid current version",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "invalid",
			candidate:  "0.1.35",
			wantUpdate: false,
			reason:     "invalid current version invalid:",
		},
		{
			name: "Invalid candidate version",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "invalid",
			wantUpdate: false,
			reason:     "invalid candidate version invalid:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewVersionChecker(tt.constraints)
			gotUpdate, gotReason := checker.ShouldUpdate(tt.current, tt.candidate)

			if gotUpdate != tt.wantUpdate {
				t.Errorf("ShouldUpdate() gotUpdate = %v, want %v", gotUpdate, tt.wantUpdate)
			}

			if tt.reason != "" && !strings.HasPrefix(gotReason, tt.reason) {
				t.Errorf("ShouldUpdate() gotReason = %q, want prefix %q", gotReason, tt.reason)
			}
		})
	}
}

func TestVersionChecker_Nil(t *testing.T) {
	// Test that nil constraints work with defaults
	checker := NewVersionChecker(nil)
	if checker.constraints == nil {
		t.Error("NewVersionChecker with nil should create default constraints")
	}

	// Should allow patch and minor updates by default
	update, _ := checker.ShouldUpdate("0.1.34", "0.1.35")
	if !update {
		t.Error("Default constraints should allow patch updates")
	}

	update, _ = checker.ShouldUpdate("0.1.34", "0.2.0")
	if !update {
		t.Error("Default constraints should allow minor updates")
	}

	// Should block major updates by default
	update, reason := checker.ShouldUpdate("0.9.9", "1.0.0")
	if update {
		t.Errorf("Default constraints should block major updates, got reason: %s", reason)
	}
}

func TestVersionChecker_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		constraints *config.VersionConstraints
		current     string
		candidate   string
		wantUpdate  bool
	}{
		{
			name: "Version with v prefix - current",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "v0.1.34",
			candidate:  "0.1.35",
			wantUpdate: true,
		},
		{
			name: "Version with v prefix - candidate",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34",
			candidate:  "v0.1.35",
			wantUpdate: true,
		},
		{
			name: "Both with v prefix",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "v0.1.34",
			candidate:  "v0.1.35",
			wantUpdate: true,
		},
		{
			name: "Version with build metadata",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34+build123",
			candidate:  "0.1.35+build456",
			wantUpdate: true,
		},
		{
			name: "Version with prerelease",
			constraints: &config.VersionConstraints{
				AutoUpdateMinor: true,
				AutoUpdateMajor: false,
			},
			current:    "0.1.34-alpha",
			candidate:  "0.1.34-beta",
			wantUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewVersionChecker(tt.constraints)
			gotUpdate, _ := checker.ShouldUpdate(tt.current, tt.candidate)

			if gotUpdate != tt.wantUpdate {
				t.Errorf("ShouldUpdate() = %v, want %v", gotUpdate, tt.wantUpdate)
			}
		})
	}
}
