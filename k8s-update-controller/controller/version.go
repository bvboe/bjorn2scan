package controller

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/bvboe/b2s-go/k8s-update-controller/config"
)

// VersionChecker evaluates version constraints
type VersionChecker struct {
	constraints *config.VersionConstraints
}

// NewVersionChecker creates a new version checker
func NewVersionChecker(constraints *config.VersionConstraints) *VersionChecker {
	// Use defaults if nil
	if constraints == nil {
		constraints = &config.VersionConstraints{
			AutoUpdateMinor: true,
			AutoUpdateMajor: false,
		}
	}
	return &VersionChecker{
		constraints: constraints,
	}
}

// ShouldUpdate determines if an update should be performed
func (vc *VersionChecker) ShouldUpdate(current, candidate string) (bool, string) {
	// Parse versions
	currentVer, err := semver.NewVersion(current)
	if err != nil {
		return false, fmt.Sprintf("invalid current version %s: %v", current, err)
	}

	candidateVer, err := semver.NewVersion(candidate)
	if err != nil {
		return false, fmt.Sprintf("invalid candidate version %s: %v", candidate, err)
	}

	// 1. If pinned to specific version
	if vc.constraints.PinnedVersion != "" {
		if candidate == vc.constraints.PinnedVersion && candidate != current {
			return true, "pinned version match"
		}
		return false, fmt.Sprintf("pinned to version %s", vc.constraints.PinnedVersion)
	}

	// 2. Check if candidate is newer
	if !candidateVer.GreaterThan(currentVer) {
		return false, "candidate version is not newer"
	}

	// 3. Check min/max bounds
	if vc.constraints.MinVersion != "" {
		minVer, err := semver.NewVersion(vc.constraints.MinVersion)
		if err == nil && candidateVer.LessThan(minVer) {
			return false, fmt.Sprintf("candidate below minimum version %s", vc.constraints.MinVersion)
		}
	}

	if vc.constraints.MaxVersion != "" {
		maxVer, err := semver.NewVersion(vc.constraints.MaxVersion)
		if err == nil && candidateVer.GreaterThan(maxVer) {
			return false, fmt.Sprintf("candidate above maximum version %s", vc.constraints.MaxVersion)
		}
	}

	// 4. Check major version constraint
	if candidateVer.Major() > currentVer.Major() && !vc.constraints.AutoUpdateMajor {
		return false, fmt.Sprintf("major version update (%d → %d) not allowed", currentVer.Major(), candidateVer.Major())
	}

	// 5. Check minor version constraint
	if candidateVer.Major() == currentVer.Major() &&
		candidateVer.Minor() > currentVer.Minor() &&
		!vc.constraints.AutoUpdateMinor {
		return false, fmt.Sprintf("minor version update (%d.%d → %d.%d) not allowed",
			currentVer.Major(), currentVer.Minor(),
			candidateVer.Major(), candidateVer.Minor())
	}

	// All checks passed
	return true, "version constraints satisfied"
}

// FindLatestVersion finds the latest version from a list that matches constraints
func (vc *VersionChecker) FindLatestVersion(current string, candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("no candidate versions provided")
	}

	// Parse current version
	currentVer, err := semver.NewVersion(current)
	if err != nil {
		return "", fmt.Errorf("invalid current version: %w", err)
	}

	var latestVer *semver.Version
	var latestStr string

	for _, candidate := range candidates {
		candidateVer, err := semver.NewVersion(candidate)
		if err != nil {
			// Skip invalid versions
			continue
		}

		// Must be newer than current
		if !candidateVer.GreaterThan(currentVer) {
			continue
		}

		// Check if this is the latest so far
		if latestVer == nil || candidateVer.GreaterThan(latestVer) {
			// Quick constraint check (detailed check done later)
			shouldUpdate, _ := vc.ShouldUpdate(current, candidate)
			if shouldUpdate {
				latestVer = candidateVer
				latestStr = candidate
			}
		}
	}

	if latestStr == "" {
		return current, nil // No newer version found
	}

	return latestStr, nil
}
