package config

import (
	"os"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

func TestConfig_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "Valid complete config",
			yaml: `
enabled: true
versionConstraints:
  autoUpdateMinor: true
  autoUpdateMajor: false
  pinnedVersion: ""
  minVersion: "0.1.0"
  maxVersion: "1.0.0"
helm:
  releaseName: "bjorn2scan"
  namespace: "bjorn2scan"
  chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan"
rollback:
  enabled: true
  healthCheckDelay: "5m"
  autoRollback: true
verification:
  enabled: false
  cosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*"
  cosignOIDCIssuer: "https://token.actions.githubusercontent.com"
`,
			wantErr: false,
		},
		{
			name: "Minimal config",
			yaml: `
enabled: true
helm:
  chartRegistry: "oci://ghcr.io/test/chart"
`,
			wantErr: false,
		},
		{
			name:    "Invalid YAML",
			yaml:    `not: valid: yaml:`,
			wantErr: true,
		},
		{
			name:    "Empty config",
			yaml:    ``,
			wantErr: false, // Empty is valid, will use defaults
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := yaml.Unmarshal([]byte(tt.yaml), &cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSetDefaults(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantCfg  Config
	}{
		{
			name: "Empty config gets all defaults",
			cfg:  Config{},
			wantCfg: Config{
				Helm: HelmConfig{
					Namespace:     "bjorn2scan",
					ReleaseName:   "bjorn2scan",
					ChartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
				},
				Verification: VerificationConfig{
					CosignOIDCIssuer:     "https://token.actions.githubusercontent.com",
					CosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*",
				},
			},
		},
		{
			name: "Partial config preserves values",
			cfg: Config{
				Helm: HelmConfig{
					Namespace: "custom-namespace",
				},
			},
			wantCfg: Config{
				Helm: HelmConfig{
					Namespace:     "custom-namespace",
					ReleaseName:   "bjorn2scan",
					ChartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
				},
				Verification: VerificationConfig{
					CosignOIDCIssuer:     "https://token.actions.githubusercontent.com",
					CosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*",
				},
			},
		},
		{
			name: "Full config unchanged",
			cfg: Config{
				Helm: HelmConfig{
					Namespace:     "custom",
					ReleaseName:   "custom-release",
					ChartRegistry: "oci://custom.registry/chart",
				},
				Verification: VerificationConfig{
					CosignOIDCIssuer:     "https://custom.issuer",
					CosignIdentityRegexp: "https://custom/*",
				},
			},
			wantCfg: Config{
				Helm: HelmConfig{
					Namespace:     "custom",
					ReleaseName:   "custom-release",
					ChartRegistry: "oci://custom.registry/chart",
				},
				Verification: VerificationConfig{
					CosignOIDCIssuer:     "https://custom.issuer",
					CosignIdentityRegexp: "https://custom/*",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDefaults(&tt.cfg)

			if tt.cfg.Helm.Namespace != tt.wantCfg.Helm.Namespace {
				t.Errorf("Namespace = %q, want %q", tt.cfg.Helm.Namespace, tt.wantCfg.Helm.Namespace)
			}
			if tt.cfg.Helm.ReleaseName != tt.wantCfg.Helm.ReleaseName {
				t.Errorf("ReleaseName = %q, want %q", tt.cfg.Helm.ReleaseName, tt.wantCfg.Helm.ReleaseName)
			}
			if tt.cfg.Helm.ChartRegistry != tt.wantCfg.Helm.ChartRegistry {
				t.Errorf("ChartRegistry = %q, want %q", tt.cfg.Helm.ChartRegistry, tt.wantCfg.Helm.ChartRegistry)
			}
			if tt.cfg.Verification.CosignOIDCIssuer != tt.wantCfg.Verification.CosignOIDCIssuer {
				t.Errorf("CosignOIDCIssuer = %q, want %q", tt.cfg.Verification.CosignOIDCIssuer, tt.wantCfg.Verification.CosignOIDCIssuer)
			}
			if tt.cfg.Verification.CosignIdentityRegexp != tt.wantCfg.Verification.CosignIdentityRegexp {
				t.Errorf("CosignIdentityRegexp = %q, want %q", tt.cfg.Verification.CosignIdentityRegexp, tt.wantCfg.Verification.CosignIdentityRegexp)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid config",
			cfg: Config{
				Helm: HelmConfig{
					ChartRegistry: "oci://ghcr.io/test/chart",
				},
			},
			wantErr: false,
		},
		{
			name: "Missing chart registry",
			cfg: Config{
				Helm: HelmConfig{
					ChartRegistry: "",
				},
			},
			wantErr: true,
			errMsg:  "helm.chartRegistry is required",
		},
		{
			name: "Verification enabled without identity regexp",
			cfg: Config{
				Helm: HelmConfig{
					ChartRegistry: "oci://ghcr.io/test/chart",
				},
				Verification: VerificationConfig{
					Enabled:              true,
					CosignIdentityRegexp: "",
				},
			},
			wantErr: true,
			errMsg:  "verification.cosignIdentityRegexp is required when verification is enabled",
		},
		{
			name: "Verification enabled with identity regexp",
			cfg: Config{
				Helm: HelmConfig{
					ChartRegistry: "oci://ghcr.io/test/chart",
				},
				Verification: VerificationConfig{
					Enabled:              true,
					CosignIdentityRegexp: "https://github.com/*",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("validate() error message = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestRollbackConfig_ParseDurations(t *testing.T) {
	tests := []struct {
		name        string
		delayStr    string
		wantDelay   time.Duration
		wantErr     bool
	}{
		{
			name:      "Valid duration string",
			delayStr:  "5m",
			wantDelay: 5 * time.Minute,
			wantErr:   false,
		},
		{
			name:      "Empty string uses default",
			delayStr:  "",
			wantDelay: 5 * time.Minute,
			wantErr:   false,
		},
		{
			name:      "Seconds duration",
			delayStr:  "30s",
			wantDelay: 30 * time.Second,
			wantErr:   false,
		},
		{
			name:      "Hours duration",
			delayStr:  "2h",
			wantDelay: 2 * time.Hour,
			wantErr:   false,
		},
		{
			name:      "Complex duration",
			delayStr:  "1h30m",
			wantDelay: 90 * time.Minute,
			wantErr:   false,
		},
		{
			name:     "Invalid duration",
			delayStr: "invalid",
			wantErr:  true,
		},
		{
			name:     "Invalid format",
			delayStr: "5 minutes",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RollbackConfig{
				HealthCheckDelayStr: tt.delayStr,
			}

			err := r.ParseDurations()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDurations() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if r.HealthCheckDelay() != tt.wantDelay {
					t.Errorf("HealthCheckDelay() = %v, want %v", r.HealthCheckDelay(), tt.wantDelay)
				}
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		want         string
	}{
		{
			name:         "Environment variable set",
			key:          "TEST_VAR",
			defaultValue: "default",
			envValue:     "custom",
			want:         "custom",
		},
		{
			name:         "Environment variable not set",
			key:          "TEST_VAR_UNSET",
			defaultValue: "default",
			envValue:     "",
			want:         "default",
		},
		{
			name:         "Empty default value",
			key:          "TEST_VAR_EMPTY",
			defaultValue: "",
			envValue:     "",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			_ = os.Unsetenv(tt.key)

			// Set environment variable if specified
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.key) }()
			}

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionConstraints_Structure(t *testing.T) {
	// Test VersionConstraints structure and YAML mapping
	yamlData := `
autoUpdateMinor: true
autoUpdateMajor: false
pinnedVersion: "0.1.35"
minVersion: "0.1.0"
maxVersion: "1.0.0"
`
	var vc VersionConstraints
	err := yaml.Unmarshal([]byte(yamlData), &vc)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !vc.AutoUpdateMinor {
		t.Error("AutoUpdateMinor should be true")
	}
	if vc.AutoUpdateMajor {
		t.Error("AutoUpdateMajor should be false")
	}
	if vc.PinnedVersion != "0.1.35" {
		t.Errorf("PinnedVersion = %q, want %q", vc.PinnedVersion, "0.1.35")
	}
	if vc.MinVersion != "0.1.0" {
		t.Errorf("MinVersion = %q, want %q", vc.MinVersion, "0.1.0")
	}
	if vc.MaxVersion != "1.0.0" {
		t.Errorf("MaxVersion = %q, want %q", vc.MaxVersion, "1.0.0")
	}
}

func TestHelmConfig_Structure(t *testing.T) {
	// Test HelmConfig structure and YAML mapping
	yamlData := `
releaseName: "test-release"
namespace: "test-namespace"
chartRegistry: "oci://test.registry/chart"
`
	var hc HelmConfig
	err := yaml.Unmarshal([]byte(yamlData), &hc)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if hc.ReleaseName != "test-release" {
		t.Errorf("ReleaseName = %q, want %q", hc.ReleaseName, "test-release")
	}
	if hc.Namespace != "test-namespace" {
		t.Errorf("Namespace = %q, want %q", hc.Namespace, "test-namespace")
	}
	if hc.ChartRegistry != "oci://test.registry/chart" {
		t.Errorf("ChartRegistry = %q, want %q", hc.ChartRegistry, "oci://test.registry/chart")
	}
}

func TestVerificationConfig_Structure(t *testing.T) {
	// Test VerificationConfig structure and YAML mapping
	yamlData := `
enabled: true
cosignIdentityRegexp: "https://github.com/test/*"
cosignOIDCIssuer: "https://token.test.com"
`
	var vc VerificationConfig
	err := yaml.Unmarshal([]byte(yamlData), &vc)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !vc.Enabled {
		t.Error("Enabled should be true")
	}
	if vc.CosignIdentityRegexp != "https://github.com/test/*" {
		t.Errorf("CosignIdentityRegexp = %q, want %q", vc.CosignIdentityRegexp, "https://github.com/test/*")
	}
	if vc.CosignOIDCIssuer != "https://token.test.com" {
		t.Errorf("CosignOIDCIssuer = %q, want %q", vc.CosignOIDCIssuer, "https://token.test.com")
	}
}

/*
Integration Tests Needed (require Kubernetes cluster):

1. TestLoadConfig_Success
   - Create ConfigMap with valid config
   - Call LoadConfig()
   - Verify config loaded correctly
   - Clean up ConfigMap

2. TestLoadConfig_ConfigMapNotFound
   - Don't create ConfigMap
   - Call LoadConfig()
   - Verify appropriate error
   - Or test with missing namespace

3. TestLoadConfig_InvalidYAML
   - Create ConfigMap with invalid YAML
   - Call LoadConfig()
   - Verify parse error

4. TestLoadConfig_MissingKey
   - Create ConfigMap without config.yaml key
   - Call LoadConfig()
   - Verify key not found error

5. TestLoadConfig_ValidationFailure
   - Create ConfigMap with invalid config (missing required fields)
   - Call LoadConfig()
   - Verify validation error

6. TestLoadConfig_EnvironmentOverrides
   - Set CONFIG_MAP_NAME, CONFIG_MAP_NAMESPACE env vars
   - Create ConfigMap in custom location
   - Call LoadConfig()
   - Verify config loaded from custom location
   - Clean up

These integration tests should be in a separate file with build tags.
*/
