package exclusions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultNetworkFilesystemTypes(t *testing.T) {
	requiredTypes := []string{
		"nfs", "nfs4", "cifs", "smbfs",
		"fuse.sshfs", "fuse.rclone", "fuse.s3fs",
	}

	typeSet := make(map[string]bool)
	for _, t := range DefaultNetworkFilesystemTypes {
		typeSet[t] = true
	}

	for _, required := range requiredTypes {
		if !typeSet[required] {
			t.Errorf("DefaultNetworkFilesystemTypes missing required type: %s", required)
		}
	}
}

func TestMountDetectionConfig_GetEffectiveNetworkTypes(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *MountDetectionConfig
		contains []string
	}{
		{
			name:     "nil config returns defaults",
			cfg:      nil,
			contains: []string{"nfs", "nfs4", "cifs"},
		},
		{
			name:     "empty extras returns defaults",
			cfg:      &MountDetectionConfig{ExtraNetworkTypes: []string{}},
			contains: []string{"nfs", "nfs4", "cifs"},
		},
		{
			name:     "extras are added",
			cfg:      &MountDetectionConfig{ExtraNetworkTypes: []string{"fuse.gdrive", "fuse.dropbox"}},
			contains: []string{"nfs", "nfs4", "cifs", "fuse.gdrive", "fuse.dropbox"},
		},
		{
			name:     "duplicates are removed",
			cfg:      &MountDetectionConfig{ExtraNetworkTypes: []string{"nfs", "fuse.gdrive"}},
			contains: []string{"nfs", "fuse.gdrive"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.GetEffectiveNetworkTypes()
			resultSet := make(map[string]bool)
			for _, t := range result {
				resultSet[t] = true
			}

			for _, expected := range tt.contains {
				if !resultSet[expected] {
					t.Errorf("GetEffectiveNetworkTypes() missing %s", expected)
				}
			}
		})
	}
}

func TestMountDetectionConfig_NoDuplicates(t *testing.T) {
	cfg := &MountDetectionConfig{
		ExtraNetworkTypes: []string{"nfs", "nfs4"}, // Both already in defaults
	}
	result := cfg.GetEffectiveNetworkTypes()

	// Count occurrences of nfs
	count := 0
	for _, t := range result {
		if t == "nfs" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("GetEffectiveNetworkTypes() has %d occurrences of nfs, want 1", count)
	}
}

func TestParseMounts(t *testing.T) {
	tmpDir := t.TempDir()
	mountsPath := filepath.Join(tmpDir, "mounts")

	mountsContent := `rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
192.168.1.100:/export/data /mnt/nfs nfs4 rw,relatime,vers=4.2,rsize=1048576,wsize=1048576 0 0
//server/share /mnt/cifs cifs rw,relatime,vers=3.0,username=user 0 0
user@server:/remote /mnt/sshfs fuse.sshfs rw,nosuid,nodev,relatime 0 0
`
	err := os.WriteFile(mountsPath, []byte(mountsContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test mounts file: %v", err)
	}

	mounts, err := ParseMounts(mountsPath)
	if err != nil {
		t.Fatalf("ParseMounts() error = %v", err)
	}

	if len(mounts) != 6 {
		t.Errorf("ParseMounts() returned %d mounts, want 6", len(mounts))
	}

	// Check specific entries
	expectedMounts := map[string]string{
		"/mnt/nfs":   "nfs4",
		"/mnt/cifs":  "cifs",
		"/mnt/sshfs": "fuse.sshfs",
	}

	for _, m := range mounts {
		if expectedType, ok := expectedMounts[m.MountPoint]; ok {
			if m.FSType != expectedType {
				t.Errorf("Mount %s has FSType %s, want %s", m.MountPoint, m.FSType, expectedType)
			}
		}
	}
}

func TestParseMounts_FileNotFound(t *testing.T) {
	_, err := ParseMounts("/nonexistent/path")
	if err == nil {
		t.Error("ParseMounts() should return error for non-existent file")
	}
}

func TestDetectNetworkMounts(t *testing.T) {
	tests := []struct {
		name           string
		mountsContent  string
		cfg            *MountDetectionConfig
		expectedMounts []string
	}{
		{
			name: "detects NFS mounts",
			mountsContent: `rootfs / rootfs rw 0 0
192.168.1.100:/data /mnt/data nfs4 rw 0 0
`,
			cfg:            nil,
			expectedMounts: []string{"/mnt/data"},
		},
		{
			name: "detects CIFS mounts",
			mountsContent: `rootfs / rootfs rw 0 0
//server/share /mnt/share cifs rw 0 0
`,
			cfg:            nil,
			expectedMounts: []string{"/mnt/share"},
		},
		{
			name: "detects FUSE network mounts",
			mountsContent: `rootfs / rootfs rw 0 0
user@host:/path /mnt/remote fuse.sshfs rw 0 0
bucket /mnt/s3 fuse.s3fs rw 0 0
`,
			cfg:            nil,
			expectedMounts: []string{"/mnt/remote", "/mnt/s3"},
		},
		{
			name: "detects extra network types",
			mountsContent: `rootfs / rootfs rw 0 0
gdrive:/ /mnt/gdrive fuse.gdrive rw 0 0
`,
			cfg:            &MountDetectionConfig{ExtraNetworkTypes: []string{"fuse.gdrive"}},
			expectedMounts: []string{"/mnt/gdrive"},
		},
		{
			name: "no network mounts",
			mountsContent: `rootfs / rootfs rw 0 0
/dev/sda1 /boot ext4 rw 0 0
tmpfs /tmp tmpfs rw 0 0
`,
			cfg:            nil,
			expectedMounts: nil,
		},
		{
			name: "multiple network mounts",
			mountsContent: `rootfs / rootfs rw 0 0
192.168.1.100:/data /mnt/nfs1 nfs4 rw 0 0
192.168.1.101:/backup /mnt/nfs2 nfs rw 0 0
//server/share /mnt/cifs cifs rw 0 0
`,
			cfg:            nil,
			expectedMounts: []string{"/mnt/nfs1", "/mnt/nfs2", "/mnt/cifs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			mountsPath := filepath.Join(tmpDir, "mounts")
			err := os.WriteFile(mountsPath, []byte(tt.mountsContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test mounts file: %v", err)
			}

			result, err := DetectNetworkMounts(mountsPath, tt.cfg)
			if err != nil {
				t.Fatalf("DetectNetworkMounts() error = %v", err)
			}

			if len(result) != len(tt.expectedMounts) {
				t.Errorf("DetectNetworkMounts() returned %d mounts, want %d: got %v", len(result), len(tt.expectedMounts), result)
				return
			}

			resultSet := make(map[string]bool)
			for _, m := range result {
				resultSet[m] = true
			}
			for _, expected := range tt.expectedMounts {
				if !resultSet[expected] {
					t.Errorf("DetectNetworkMounts() missing expected mount: %s", expected)
				}
			}
		})
	}
}

func TestGenerateNetworkExclusions(t *testing.T) {
	tests := []struct {
		name              string
		mountsContent     string
		cfg               *MountDetectionConfig
		expectedPatterns  []string
		expectedNotHave   []string
	}{
		{
			name: "generates patterns for NFS mounts",
			mountsContent: `rootfs / rootfs rw 0 0
192.168.1.100:/data /mnt/data nfs4 rw 0 0
`,
			cfg:              nil,
			expectedPatterns: []string{"**/mnt/data/**"},
		},
		{
			name: "handles nested mount points",
			mountsContent: `rootfs / rootfs rw 0 0
192.168.1.100:/data /mnt/nested/deep/path nfs4 rw 0 0
`,
			cfg:              nil,
			expectedPatterns: []string{"**/mnt/nested/deep/path/**"},
		},
		{
			name: "no patterns for no network mounts",
			mountsContent: `rootfs / rootfs rw 0 0
/dev/sda1 /boot ext4 rw 0 0
`,
			cfg:              nil,
			expectedPatterns: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			mountsPath := filepath.Join(tmpDir, "mounts")
			err := os.WriteFile(mountsPath, []byte(tt.mountsContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test mounts file: %v", err)
			}

			result, err := GenerateNetworkExclusions(mountsPath, tt.cfg)
			if err != nil {
				t.Fatalf("GenerateNetworkExclusions() error = %v", err)
			}

			if len(result) != len(tt.expectedPatterns) {
				t.Errorf("GenerateNetworkExclusions() returned %d patterns, want %d: got %v", len(result), len(tt.expectedPatterns), result)
				return
			}

			resultSet := make(map[string]bool)
			for _, p := range result {
				resultSet[p] = true
			}
			for _, expected := range tt.expectedPatterns {
				if !resultSet[expected] {
					t.Errorf("GenerateNetworkExclusions() missing expected pattern: %s", expected)
				}
			}
		})
	}
}

func TestGetProcMountsPath(t *testing.T) {
	tests := []struct {
		name       string
		hostPrefix string
		expected   string
	}{
		{
			name:       "empty prefix",
			hostPrefix: "",
			expected:   "/proc/mounts",
		},
		{
			name:       "host prefix",
			hostPrefix: "/host",
			expected:   "/host/proc/mounts",
		},
		{
			name:       "host prefix with trailing slash",
			hostPrefix: "/host/",
			expected:   "/host/proc/mounts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetProcMountsPath(tt.hostPrefix)
			if result != tt.expected {
				t.Errorf("GetProcMountsPath(%q) = %q, want %q", tt.hostPrefix, result, tt.expected)
			}
		})
	}
}
