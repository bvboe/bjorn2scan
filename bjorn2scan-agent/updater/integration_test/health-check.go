//go:build integration
// +build integration

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/bvboe/b2s-go/bjorn2scan-agent/updater"
)

// healthCheck simulates the agent restart and post-update health check
// This should be called after test-driver completes to verify the update
func main() {
	fmt.Println("Running post-update health check...")

	// Create installer with default paths
	installer := updater.NewInstaller("", "", 10*time.Second)

	// Check if rollback check is needed
	if !installer.ShouldCheckRollback() {
		fmt.Println("No pending update detected")
		return
	}

	// Perform health check (will commit or rollback)
	if err := installer.PerformPostUpdateHealthCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "Health check/rollback failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Health check completed successfully")
}
