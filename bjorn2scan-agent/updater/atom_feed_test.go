package updater

import (
	"testing"
	"time"
)

func TestExtractTagFromID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "standard GitHub format",
			id:       "tag:github.com,2008:Repository/1114756634/v0.1.72",
			expected: "v0.1.72",
		},
		{
			name:     "version without v prefix",
			id:       "tag:github.com,2008:Repository/1114756634/0.1.72",
			expected: "0.1.72",
		},
		{
			name:     "prerelease version",
			id:       "tag:github.com,2008:Repository/123456/v1.0.0-rc1",
			expected: "v1.0.0-rc1",
		},
		{
			name:     "empty string",
			id:       "",
			expected: "",
		},
		{
			name:     "no slashes",
			id:       "some-random-string",
			expected: "",
		},
		{
			name:     "trailing slash",
			id:       "tag:github.com,2008:Repository/123/",
			expected: "",
		},
		{
			name:     "single slash at end",
			id:       "/v1.0.0",
			expected: "v1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTagFromID(tt.id)
			if result != tt.expected {
				t.Errorf("extractTagFromID(%q) = %q, want %q", tt.id, result, tt.expected)
			}
		})
	}
}

func TestIsReleaseReady(t *testing.T) {
	tests := []struct {
		name     string
		entry    AtomEntry
		expected bool
	}{
		{
			name: "release ready - title matches tag",
			entry: AtomEntry{
				ID:      "tag:github.com,2008:Repository/1114756634/v0.1.72",
				Title:   "v0.1.72",
				Updated: time.Now(),
			},
			expected: true,
		},
		{
			name: "tag only - title contains annotation content",
			entry: AtomEntry{
				ID:      "tag:github.com,2008:Repository/1114756634/v0.1.72",
				Title:   "v0.1.72: ## 🎯 Highlights",
				Updated: time.Now(),
			},
			expected: false,
		},
		{
			name: "tag only - title has extra description",
			entry: AtomEntry{
				ID:      "tag:github.com,2008:Repository/123456/v1.0.0",
				Title:   "v1.0.0: Initial release",
				Updated: time.Now(),
			},
			expected: false,
		},
		{
			name: "empty ID",
			entry: AtomEntry{
				ID:      "",
				Title:   "v1.0.0",
				Updated: time.Now(),
			},
			expected: false,
		},
		{
			name: "invalid ID format",
			entry: AtomEntry{
				ID:      "not-a-valid-id",
				Title:   "v1.0.0",
				Updated: time.Now(),
			},
			expected: false,
		},
		{
			name: "prerelease version - ready",
			entry: AtomEntry{
				ID:      "tag:github.com,2008:Repository/123456/v1.0.0-rc1",
				Title:   "v1.0.0-rc1",
				Updated: time.Now(),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isReleaseReady(tt.entry)
			if result != tt.expected {
				t.Errorf("isReleaseReady() = %v, want %v (ID: %q, Title: %q)",
					result, tt.expected, tt.entry.ID, tt.entry.Title)
			}
		})
	}
}
