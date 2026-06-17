package syft

import (
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/sbom-generator-shared/exclusions"
)

// TestDefaultHostExclusions_ContainsContainerPaths tests that container paths are excluded
func TestDefaultHostExclusions_ContainsContainerPaths(t *testing.T) {
	requiredPatterns := []string{
		"**/snapshots/**",      // containerd snapshots
		"**/rootfs/**",         // containerd rootfs
		"**/overlay2/**",       // docker overlay
		"**/var/lib/docker/**", // docker data
		"**/var/lib/containerd/**",
		"**/var/lib/kubelet/pods/**",
	}

	for _, pattern := range requiredPatterns {
		found := false
		for _, excl := range exclusions.DefaultHostExclusions {
			if excl == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected exclusion pattern %q not found in DefaultHostExclusions", pattern)
		}
	}
}

// TestDefaultHostExclusions_ContainsSystemPaths tests that system paths are excluded
func TestDefaultHostExclusions_ContainsSystemPaths(t *testing.T) {
	requiredPatterns := []string{
		"**/proc/**",
		"**/sys/**",
		"**/dev/**",
		"**/run/**",
		"**/tmp/**",
	}

	for _, pattern := range requiredPatterns {
		found := false
		for _, excl := range exclusions.DefaultHostExclusions {
			if excl == pattern {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected exclusion pattern %q not found in DefaultHostExclusions", pattern)
		}
	}
}

// TestDefaultHostExclusions_HasMinimumCount tests that we have enough exclusions
func TestDefaultHostExclusions_HasMinimumCount(t *testing.T) {
	// We expect at least 10 exclusion patterns for container and system paths
	minCount := 10
	if len(exclusions.DefaultHostExclusions) < minCount {
		t.Errorf("Expected at least %d exclusion patterns, got %d", minCount, len(exclusions.DefaultHostExclusions))
	}
}

// TestDefaultHostExclusions_AllAreGlobPatterns tests that all patterns are valid globs
func TestDefaultHostExclusions_AllAreGlobPatterns(t *testing.T) {
	for _, pattern := range exclusions.DefaultHostExclusions {
		// All patterns should contain ** for recursive matching
		if !strings.Contains(pattern, "**") {
			t.Errorf("Pattern %q doesn't appear to be a recursive glob (missing **)", pattern)
		}
		// Patterns should not be empty
		if len(pattern) == 0 {
			t.Error("Found empty exclusion pattern")
		}
	}
}

// TestDefaultHostExclusions_NoAbsolutePaths tests that patterns use relative globs
func TestDefaultHostExclusions_NoAbsolutePaths(t *testing.T) {
	for _, pattern := range exclusions.DefaultHostExclusions {
		// Patterns should start with ** not with /
		if strings.HasPrefix(pattern, "/") {
			t.Errorf("Pattern %q starts with / but should use ** for portability", pattern)
		}
	}
}

// TestDefaultHostExclusions_IncludesRancherForK3s tests K3s/Rancher exclusion
func TestDefaultHostExclusions_IncludesRancherForK3s(t *testing.T) {
	found := false
	for _, excl := range exclusions.DefaultHostExclusions {
		if strings.Contains(excl, "rancher") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected rancher exclusion pattern for K3s support")
	}
}

// TestHostScanConfig tests the host scan configuration
func TestHostScanConfig(t *testing.T) {
	// Test default config
	defaultCfg := DefaultHostScanConfig()
	if !defaultCfg.AutoDetectNFS {
		t.Error("Expected AutoDetectNFS to be true by default")
	}
	if defaultCfg.ExtraExclusions != nil {
		t.Error("Expected ExtraExclusions to be nil by default")
	}
	if defaultCfg.ExtraNetworkFSTypes != nil {
		t.Error("Expected ExtraNetworkFSTypes to be nil by default")
	}

	// Test SetHostScanConfig
	customCfg := HostScanConfig{
		ExtraExclusions:     []string{"**/custom/**"},
		AutoDetectNFS:       false,
		ExtraNetworkFSTypes: []string{"fuse.gdrive"},
	}
	SetHostScanConfig(customCfg)

	// Verify the config was set (we can't directly access it, so this is just a smoke test)
	if hostScanConfig.AutoDetectNFS != false {
		t.Error("Expected AutoDetectNFS to be false after SetHostScanConfig")
	}
}
