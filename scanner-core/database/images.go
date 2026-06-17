package database

import (
	"database/sql"
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// ContainerImage represents a container image in the database
type ContainerImage struct {
	ID        int64  `json:"id"`
	Digest    string `json:"digest"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// GetOrCreateImage gets an existing image or creates a new one based on digest
// Returns the image ID and whether it was newly created
func (db *DB) GetOrCreateImage(image containers.ImageID) (int64, bool, error) {
	return db.getOrCreateImageTx(db.conn, image)
}

// getOrCreateImageTx is a transaction-aware version that works with both *sql.DB and *sql.Tx
func (db *DB) getOrCreateImageTx(exec interface {
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}, image containers.ImageID) (int64, bool, error) {
	// Validate required fields
	if image.Digest == "" {
		return 0, false, fmt.Errorf("cannot create/get image without digest: reference=%s",
			image.Reference)
	}

	// Try to get existing image by digest
	var id int64
	err := exec.QueryRow(`
		SELECT id FROM images
		WHERE digest = ?
	`, image.Digest).Scan(&id)

	if err == nil {
		// Image already exists
		return id, false, nil
	}

	if err != sql.ErrNoRows {
		return 0, false, fmt.Errorf("failed to query image: %w", err)
	}

	// Image doesn't exist, create it
	result, err := exec.Exec(`
		INSERT INTO images (digest)
		VALUES (?)
	`, image.Digest)

	if err != nil {
		return 0, false, fmt.Errorf("failed to insert image: %w", err)
	}

	id, err = result.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("failed to get image ID: %w", err)
	}

	log.Debug("new image added",
		"reference", image.Reference, "digest", image.Digest, "id", id)

	return id, true, nil
}

// GetAllImages returns all container images from the database
func (db *DB) GetAllImages() (interface{}, error) {
	rows, err := db.conn.Query(`
		SELECT id, digest, status, created_at, updated_at
		FROM images
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var images []ContainerImage
	for rows.Next() {
		var img ContainerImage
		var status sql.NullString
		err := rows.Scan(&img.ID, &img.Digest,
			&status, &img.CreatedAt, &img.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan image: %w", err)
		}
		if status.Valid {
			img.Status = status.String
		} else {
			img.Status = "pending"
		}
		images = append(images, img)
	}

	return images, nil
}

// GetImageByID returns a container image by ID
func (db *DB) GetImageByID(id int64) (*ContainerImage, error) {
	var img ContainerImage
	var status sql.NullString
	err := db.conn.QueryRow(`
		SELECT id, digest, status, created_at, updated_at
		FROM images
		WHERE id = ?
	`, id).Scan(&img.ID, &img.Digest,
		&status, &img.CreatedAt, &img.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}
	if status.Valid {
		img.Status = status.String
	} else {
		img.Status = "pending"
	}
	return &img, nil
}
