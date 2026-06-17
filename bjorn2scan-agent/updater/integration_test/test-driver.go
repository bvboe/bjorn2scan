//go:build integration
// +build integration

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/bvboe/b2s-go/bjorn2scan-agent/updater"
)

// testDriver is a simple program that triggers a single update check
// Usage: test-driver <feed-url> <asset-base-url> <current-version>
func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <feed-url> <asset-base-url> <current-version>\n", os.Args[0])
		os.Exit(1)
	}

	feedURL := os.Args[1]
	assetBaseURL := os.Args[2]
	currentVersion := os.Args[3]

	fmt.Printf("Starting update check...\n")
	fmt.Printf("  Feed URL: %s\n", feedURL)
	fmt.Printf("  Asset Base URL: %s\n", assetBaseURL)
	fmt.Printf("  Current Version: %s\n", currentVersion)

	// Create updater configuration
	config := &updater.Config{
		Enabled:            true,
		CheckInterval:      1 * time.Hour, // Not used for one-time check
		FeedURL:            feedURL,
		AssetBaseURL:       assetBaseURL,
		CurrentVersion:     currentVersion,
		VerifySignatures:   false, // Disabled for testing
		RollbackEnabled:    true,
		HealthCheckTimeout: 10 * time.Second,
	}

	// Create updater
	u, err := updater.New(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create updater: %v\n", err)
		os.Exit(1)
	}

	// Trigger update check
	u.TriggerCheck()

	// Wait for update to complete (poll status)
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			fmt.Fprintf(os.Stderr, "Update check timed out\n")
			os.Exit(1)
		case <-ticker.C:
			status, errMsg, _, _, _, _ := u.GetStatus()

			if status == updater.StatusFailed {
				fmt.Fprintf(os.Stderr, "Update failed: %s\n", errMsg)
				os.Exit(1)
			}

			if status == updater.StatusIdle {
				fmt.Println("Update check completed successfully")
				return
			}

			// Still processing (StatusChecking, StatusDownloading, StatusVerifying, StatusInstalling)
			fmt.Printf("Status: %s\n", status)
		}
	}
}
