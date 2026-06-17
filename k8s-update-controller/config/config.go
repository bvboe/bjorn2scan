package config

import (
	"context"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const (
	defaultConfigMapName      = "bjorn2scan-update-config"
	defaultConfigMapNamespace = "bjorn2scan"
	defaultConfigMapKey       = "config.yaml"
)

// LoadConfig loads configuration from ConfigMap or environment variables
func LoadConfig() (*Config, error) {
	// Get ConfigMap details from environment or use defaults
	configMapName := getEnv("CONFIG_MAP_NAME", defaultConfigMapName)
	configMapNamespace := getEnv("CONFIG_MAP_NAMESPACE", defaultConfigMapNamespace)
	configMapKey := getEnv("CONFIG_MAP_KEY", defaultConfigMapKey)

	// Create Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Get ConfigMap
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cm, err := clientset.CoreV1().ConfigMaps(configMapNamespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s/%s: %w", configMapNamespace, configMapName, err)
	}

	// Get config data
	configData, ok := cm.Data[configMapKey]
	if !ok {
		return nil, fmt.Errorf("key %s not found in ConfigMap", configMapKey)
	}

	// Parse YAML
	var cfg Config
	if err := yaml.Unmarshal([]byte(configData), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Parse duration strings
	if err := cfg.Rollback.ParseDurations(); err != nil {
		return nil, fmt.Errorf("failed to parse durations: %w", err)
	}

	// Set defaults
	setDefaults(&cfg)

	// Validate configuration
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Helm.Namespace == "" {
		cfg.Helm.Namespace = "bjorn2scan"
	}
	if cfg.Helm.ReleaseName == "" {
		cfg.Helm.ReleaseName = "bjorn2scan"
	}
	if cfg.Helm.ChartRegistry == "" {
		cfg.Helm.ChartRegistry = "oci://ghcr.io/bvboe/b2s-go/bjorn2scan"
	}
	// HealthCheckDelay default is handled in ParseDurations()
	if cfg.Verification.CosignOIDCIssuer == "" {
		cfg.Verification.CosignOIDCIssuer = "https://token.actions.githubusercontent.com"
	}
	if cfg.Verification.CosignIdentityRegexp == "" {
		cfg.Verification.CosignIdentityRegexp = "https://github.com/bvboe/b2s-go/*"
	}
	if cfg.Verification.ReleaseBaseURL == "" {
		cfg.Verification.ReleaseBaseURL = "https://github.com/bvboe/b2s-go/releases/download"
	}
}

func validate(cfg *Config) error {
	if cfg.Helm.ChartRegistry == "" {
		return fmt.Errorf("helm.chartRegistry is required")
	}
	if cfg.Verification.Enabled && cfg.Verification.CosignIdentityRegexp == "" {
		return fmt.Errorf("verification.cosignIdentityRegexp is required when verification is enabled")
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
