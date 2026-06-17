package exclusions

import (
	"testing"
)

func TestDefaultHostExclusionsContainsRequiredPatterns(t *testing.T) {
	requiredPatterns := []string{
		// Container runtime paths
		"**/snapshots/**",
		"**/rootfs/**",
		"**/overlay2/**",
		"**/var/lib/kubelet/pods/**",
		"**/var/lib/containerd/**",
		"**/var/lib/docker/**",
		"**/var/lib/rancher/**",
		// System virtual filesystems
		"**/proc/**",
		"**/sys/**",
		"**/dev/**",
		"**/run/**",
		"**/tmp/**",
		// Common data mount points (Option A)
		"**/mnt/**",
		"**/media/**",
		"**/srv/**",
	}

	patternSet := make(map[string]bool)
	for _, p := range DefaultHostExclusions {
		patternSet[p] = true
	}

	for _, required := range requiredPatterns {
		if !patternSet[required] {
			t.Errorf("DefaultHostExclusions missing required pattern: %s", required)
		}
	}
}

func TestMergeExclusions(t *testing.T) {
	tests := []struct {
		name     string
		input    [][]string
		expected []string
	}{
		{
			name:     "empty input",
			input:    [][]string{},
			expected: nil,
		},
		{
			name:     "single list",
			input:    [][]string{{"a", "b", "c"}},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "multiple lists no duplicates",
			input:    [][]string{{"a", "b"}, {"c", "d"}},
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "duplicate removal",
			input:    [][]string{{"a", "b", "c"}, {"b", "c", "d"}},
			expected: []string{"a", "b", "c", "d"},
		},
		{
			name:     "preserves order first occurrence",
			input:    [][]string{{"c", "a"}, {"b", "a"}},
			expected: []string{"c", "a", "b"},
		},
		{
			name:     "empty strings filtered",
			input:    [][]string{{"a", "", "b"}, {"", "c"}},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty list in middle",
			input:    [][]string{{"a"}, {}, {"b"}},
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergeExclusions(tt.input...)
			if len(result) != len(tt.expected) {
				t.Errorf("MergeExclusions() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("MergeExclusions()[%d] = %s, want %s", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestBuildExclusions_WithoutNFS(t *testing.T) {
	cfg := HostExclusionConfig{
		AutoDetectNFS:   false,
		ExtraExclusions: []string{"**/custom/**"},
	}

	exclusions, err := BuildExclusions(cfg)
	if err != nil {
		t.Fatalf("BuildExclusions() error = %v", err)
	}

	// Should contain defaults
	found := false
	for _, e := range exclusions {
		if e == "**/proc/**" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildExclusions() missing default exclusion **/proc/**")
	}

	// Should contain extra exclusions
	found = false
	for _, e := range exclusions {
		if e == "**/custom/**" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildExclusions() missing extra exclusion **/custom/**")
	}
}

func TestBuildExclusions_DeduplicatesExtras(t *testing.T) {
	cfg := HostExclusionConfig{
		AutoDetectNFS:   false,
		ExtraExclusions: []string{"**/proc/**", "**/custom/**"}, // proc is already in defaults
	}

	exclusions, err := BuildExclusions(cfg)
	if err != nil {
		t.Fatalf("BuildExclusions() error = %v", err)
	}

	// Count occurrences of **/proc/**
	count := 0
	for _, e := range exclusions {
		if e == "**/proc/**" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("BuildExclusions() has %d occurrences of **/proc/**, want 1", count)
	}
}
