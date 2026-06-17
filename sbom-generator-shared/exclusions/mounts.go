package exclusions

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DefaultNetworkFilesystemTypes are the filesystem types considered as network filesystems.
var DefaultNetworkFilesystemTypes = []string{
	"nfs", "nfs4", "cifs", "smbfs",
	"fuse.sshfs", "fuse.rclone", "fuse.s3fs",
	"afs", "gfs", "gfs2", "lustre", "glusterfs",
}

// MountDetectionConfig allows customizing network mount detection.
type MountDetectionConfig struct {
	// ExtraNetworkTypes adds to DefaultNetworkFilesystemTypes.
	ExtraNetworkTypes []string
}

// GetEffectiveNetworkTypes returns defaults + extras.
func (c *MountDetectionConfig) GetEffectiveNetworkTypes() []string {
	if c == nil {
		return DefaultNetworkFilesystemTypes
	}
	if len(c.ExtraNetworkTypes) == 0 {
		return DefaultNetworkFilesystemTypes
	}
	// Merge defaults with extras, deduplicating
	seen := make(map[string]bool)
	var result []string
	for _, t := range DefaultNetworkFilesystemTypes {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	for _, t := range c.ExtraNetworkTypes {
		if t != "" && !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}

// MountInfo represents a single mount entry from /proc/mounts.
type MountInfo struct {
	Device     string
	MountPoint string
	FSType     string
	Options    string
}

// ParseMounts reads /proc/mounts and returns entries.
func ParseMounts(procMountsPath string) ([]MountInfo, error) {
	file, err := os.Open(procMountsPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var mounts []MountInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, MountInfo{
			Device:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

// DetectNetworkMounts returns mount points using network filesystems.
func DetectNetworkMounts(procMountsPath string, cfg *MountDetectionConfig) ([]string, error) {
	mounts, err := ParseMounts(procMountsPath)
	if err != nil {
		return nil, err
	}

	networkTypes := cfg.GetEffectiveNetworkTypes()
	typeSet := make(map[string]bool)
	for _, t := range networkTypes {
		typeSet[t] = true
	}

	var networkMounts []string
	for _, mount := range mounts {
		if typeSet[mount.FSType] {
			networkMounts = append(networkMounts, mount.MountPoint)
		}
	}
	return networkMounts, nil
}

// GenerateNetworkExclusions creates glob patterns for network mounts.
func GenerateNetworkExclusions(procMountsPath string, cfg *MountDetectionConfig) ([]string, error) {
	mounts, err := DetectNetworkMounts(procMountsPath, cfg)
	if err != nil {
		return nil, err
	}

	var exclusions []string
	for _, mountPoint := range mounts {
		// Create glob pattern: **/<mount_point>/**
		// Strip leading slash for the pattern
		cleanPath := strings.TrimPrefix(mountPoint, "/")
		if cleanPath == "" {
			continue
		}
		pattern := "**/" + cleanPath + "/**"
		exclusions = append(exclusions, pattern)
	}
	return exclusions, nil
}

// GetProcMountsPath returns path based on host prefix ("" or "/host").
func GetProcMountsPath(hostPrefix string) string {
	if hostPrefix == "" {
		return "/proc/mounts"
	}
	return filepath.Join(hostPrefix, "proc", "mounts")
}
