package runtime

import (
	"encoding/json"
	"testing"
)

func TestInjectPlatformIntoSBOM(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		arch     string
		os       string
		wantArch string
		wantOS   string
		wantErr  bool
	}{
		{
			name: "inject into directory source",
			sbom: `{
				"source": {
					"type": "directory",
					"metadata": {
						"path": "/tmp/sbom-mount-abc123"
					}
				},
				"artifacts": []
			}`,
			arch:     "arm64",
			os:       "linux",
			wantArch: "arm64",
			wantOS:   "linux",
		},
		{
			name: "inject into empty metadata",
			sbom: `{
				"source": {
					"type": "directory"
				}
			}`,
			arch:     "amd64",
			os:       "linux",
			wantArch: "amd64",
			wantOS:   "linux",
		},
		{
			name: "inject into missing source",
			sbom: `{
				"artifacts": []
			}`,
			arch:     "arm64",
			os:       "linux",
			wantArch: "arm64",
			wantOS:   "linux",
		},
		{
			name:     "invalid json",
			sbom:     `{invalid`,
			arch:     "arm64",
			os:       "linux",
			wantErr:  true,
		},
		{
			name: "preserves existing fields",
			sbom: `{
				"source": {
					"type": "directory",
					"metadata": {
						"path": "/tmp/test"
					}
				},
				"artifacts": [{"name": "test"}],
				"schema": {"version": "1.0.0"}
			}`,
			arch:     "arm64",
			os:       "linux",
			wantArch: "arm64",
			wantOS:   "linux",
		},
		{
			name: "empty os string",
			sbom: `{"source": {"type": "directory"}}`,
			arch:     "amd64",
			os:       "",
			wantArch: "amd64",
			wantOS:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := injectPlatformIntoSBOM([]byte(tt.sbom), tt.arch, tt.os)
			if (err != nil) != tt.wantErr {
				t.Errorf("injectPlatformIntoSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Parse result and verify
			var parsed map[string]interface{}
			if err := json.Unmarshal(result, &parsed); err != nil {
				t.Fatalf("failed to parse result: %v", err)
			}

			source, ok := parsed["source"].(map[string]interface{})
			if !ok {
				t.Fatal("source not found in result")
			}

			metadata, ok := source["metadata"].(map[string]interface{})
			if !ok {
				t.Fatal("metadata not found in source")
			}

			if got := metadata["architecture"]; got != tt.wantArch {
				t.Errorf("architecture = %v, want %v", got, tt.wantArch)
			}

			if tt.wantOS != "" {
				if got := metadata["os"]; got != tt.wantOS {
					t.Errorf("os = %v, want %v", got, tt.wantOS)
				}
			} else {
				// OS should not be set if empty
				if _, exists := metadata["os"]; exists {
					t.Errorf("os should not be set when empty")
				}
			}
		})
	}
}
