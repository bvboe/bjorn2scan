// Package exclusions provides shared host SBOM scanning exclusion patterns
// and utilities for merging exclusion lists.
package exclusions

// DefaultHostExclusions are the paths to exclude when scanning the host filesystem.
// These exclude container filesystems to avoid double-counting packages that
// are already scanned via container image scanning.
var DefaultHostExclusions = []string{
	// Container runtime paths
	"**/snapshots/**",            // containerd snapshots
	"**/rootfs/**",               // containerd rootfs
	"**/overlay2/**",             // docker overlay
	"**/var/lib/kubelet/pods/**", // pod volumes
	"**/var/lib/containerd/**",   // containerd data
	"**/var/lib/docker/**",       // docker data
	"**/var/lib/rancher/**",      // k3s/rancher data
	// System virtual filesystems
	"**/proc/**", // proc filesystem
	"**/sys/**",  // sys filesystem
	"**/dev/**",  // device files
	"**/run/**",  // runtime data
	"**/tmp/**",  // temporary files
	// Common data mount points (Option A)
	"**/mnt/**",   // mount points
	"**/media/**", // removable media
	"**/srv/**",   // service data
}

// MergeExclusions combines multiple exclusion lists, deduplicating entries.
// The order of items in the result is: first list items, then second list items, etc.,
// with duplicates removed (keeping the first occurrence).
func MergeExclusions(exclusionLists ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, list := range exclusionLists {
		for _, pattern := range list {
			if pattern == "" {
				continue
			}
			if !seen[pattern] {
				seen[pattern] = true
				result = append(result, pattern)
			}
		}
	}

	return result
}

// HostExclusionConfig holds configuration for building host exclusions.
type HostExclusionConfig struct {
	// ExtraExclusions are additional exclusion patterns to include.
	ExtraExclusions []string
	// AutoDetectNFS enables auto-detection of network filesystem mounts.
	AutoDetectNFS bool
	// ExtraNetworkFSTypes are additional network filesystem types to detect.
	ExtraNetworkFSTypes []string
	// HostPrefix is the prefix for the host filesystem (e.g., "/host" or "").
	HostPrefix string
}

// BuildExclusions builds the complete list of exclusions based on config.
// It combines default exclusions, network mount exclusions (if enabled),
// and any extra exclusions specified in the config.
func BuildExclusions(cfg HostExclusionConfig) ([]string, error) {
	exclusions := DefaultHostExclusions

	// Add network mount exclusions if enabled
	if cfg.AutoDetectNFS {
		mountCfg := &MountDetectionConfig{
			ExtraNetworkTypes: cfg.ExtraNetworkFSTypes,
		}
		procMountsPath := GetProcMountsPath(cfg.HostPrefix)
		networkExclusions, err := GenerateNetworkExclusions(procMountsPath, mountCfg)
		if err != nil {
			// Log warning but continue - don't fail the scan if mount detection fails
			// Return error to caller so they can log it appropriately
			return MergeExclusions(exclusions, cfg.ExtraExclusions), err
		}
		exclusions = MergeExclusions(exclusions, networkExclusions)
	}

	// Add extra exclusions from config
	return MergeExclusions(exclusions, cfg.ExtraExclusions), nil
}
