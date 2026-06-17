// Package deployment provides utilities for identifying and managing scanner deployments.
package deployment

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const uuidFileName = "deployment-uuid.txt"

// UUID represents a persistent deployment identifier.
type UUID struct {
	value    string
	filePath string
}

// NewUUID creates or loads a deployment UUID from the specified directory.
// If the UUID file doesn't exist, a new UUID is generated and persisted.
// If the file exists, the UUID is loaded from it.
func NewUUID(dataDir string) (*UUID, error) {
	filePath := filepath.Join(dataDir, uuidFileName)

	// Try to read existing UUID
	if data, err := os.ReadFile(filePath); err == nil {
		uuidStr := strings.TrimSpace(string(data))

		// Validate the UUID format
		if _, err := uuid.Parse(uuidStr); err != nil {
			return nil, fmt.Errorf("invalid UUID in %s: %w", filePath, err)
		}

		return &UUID{
			value:    uuidStr,
			filePath: filePath,
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read UUID file %s: %w", filePath, err)
	}

	// File doesn't exist, generate new UUID
	newUUID, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dataDir, err)
	}

	// Write UUID to file
	if err := os.WriteFile(filePath, []byte(newUUID+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("failed to write UUID to %s: %w", filePath, err)
	}

	return &UUID{
		value:    newUUID,
		filePath: filePath,
	}, nil
}

// String returns the UUID as a string.
func (u *UUID) String() string {
	return u.value
}

// FilePath returns the path to the UUID file.
func (u *UUID) FilePath() string {
	return u.filePath
}

// generateUUID generates a new UUID v4 using crypto/rand for security.
func generateUUID() (string, error) {
	// Use google/uuid library which uses crypto/rand by default
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// IsValidUUID checks if a string is a valid UUID.
func IsValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
