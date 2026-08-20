package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestWALSizeLimitAppliedToEveryConnection is the reason journal_size_limit lives
// in the DSN rather than in the PRAGMA block next to journal_mode.
//
// journal_size_limit is per-connection, and the pool holds 5 connections. A
// PRAGMA issued through database/sql runs on whichever connection the pool hands
// out, so setting it that way leaves it at the default (-1, unlimited) on the
// other four — including, quite possibly, the one the WAL monitor checkpoints on,
// which is the only connection where the limit actually does anything.
//
// Holding several connections open simultaneously forces the pool to open
// distinct ones; checking each in turn would just keep reusing the first.
func TestWALSizeLimitAppliedToEveryConnection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wal_limit.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	ctx := context.Background()

	// Pin several connections at once so the pool cannot satisfy them all with
	// one reused connection.
	const want = 5
	conns := make([]*sql.Conn, 0, want)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	for i := 0; i < want; i++ {
		c, err := db.conn.Conn(ctx)
		if err != nil {
			t.Fatalf("Failed to grab connection %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	for i, c := range conns {
		var limit int64
		if err := c.QueryRowContext(ctx, "PRAGMA journal_size_limit").Scan(&limit); err != nil {
			t.Fatalf("Failed to read journal_size_limit on connection %d: %v", i, err)
		}
		if limit != walSizeLimitBytes {
			t.Errorf("connection %d: journal_size_limit = %d, want %d (a -1 here means the "+
				"pragma reached only some connections and the WAL can still grow unbounded)",
				i, limit, walSizeLimitBytes)
		}
	}
}

// TestWALTruncatedToSizeLimit verifies the limit has its intended effect end to
// end: push the WAL past the cap, checkpoint, and confirm the file shrinks back.
// Without journal_size_limit the WAL stays at its high-water mark, which is the
// behaviour that produced a 1.31GB WAL in production.
//
// Note the write after the checkpoint. Truncation happens when the WAL resets,
// not when the checkpoint runs, so a FULL checkpoint on its own leaves the file
// at full size and the assertion only holds once something writes again.
func TestWALTruncatedToSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping WAL growth test in short mode")
	}

	dbPath := filepath.Join(t.TempDir(), "wal_truncate.db")

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	ctx := context.Background()

	// All writes go through one pinned connection. journal_size_limit is
	// per-connection, so the connection that lowers the limit for the test has to
	// be the same one that writes and checkpoints — going through the pool would
	// scatter those across connections. PRAGMA takes no bound parameters.
	writer, err := db.conn.Conn(ctx)
	if err != nil {
		t.Fatalf("Failed to open writer connection: %v", err)
	}
	defer func() { _ = writer.Close() }()

	const testLimit = 64 * 1024
	if _, err := writer.ExecContext(ctx,
		fmt.Sprintf("PRAGMA journal_size_limit = %d", testLimit)); err != nil {
		t.Fatalf("Failed to set test journal_size_limit: %v", err)
	}
	if _, err := writer.ExecContext(ctx, `CREATE TABLE wal_growth (id INTEGER PRIMARY KEY, payload TEXT)`); err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Hold a read open across the writes. This is what stops SQLite rewinding the
	// WAL on its own, and mirrors the streaming /metrics readers in production.
	reader, err := db.conn.Conn(ctx)
	if err != nil {
		t.Fatalf("Failed to open reader connection: %v", err)
	}
	rows, err := reader.QueryContext(ctx, "SELECT id FROM wal_growth")
	if err != nil {
		t.Fatalf("Failed to start read: %v", err)
	}

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = 'x'
	}
	for i := 0; i < 400; i++ {
		if _, err := writer.ExecContext(ctx, `INSERT INTO wal_growth (payload) VALUES (?)`, string(payload)); err != nil {
			t.Fatalf("Insert %d failed: %v", i, err)
		}
	}

	walPath := dbPath + "-wal"
	grown, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Failed to stat WAL: %v", err)
	}
	if grown.Size() <= testLimit {
		t.Skipf("WAL only reached %d bytes, never exceeded the %d limit — nothing to truncate",
			grown.Size(), testLimit)
	}

	// Release the reader so the checkpoint can complete, then checkpoint.
	if err := rows.Close(); err != nil {
		t.Fatalf("Failed to close rows: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Failed to close reader connection: %v", err)
	}
	if _, err := writer.ExecContext(ctx, "PRAGMA wal_checkpoint(FULL)"); err != nil {
		t.Fatalf("Checkpoint failed: %v", err)
	}

	// The reset — and with it the truncation — happens on the next write.
	if _, err := writer.ExecContext(ctx, `INSERT INTO wal_growth (payload) VALUES ('trigger reset')`); err != nil {
		t.Fatalf("Post-checkpoint insert failed: %v", err)
	}

	after, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("Failed to stat WAL after checkpoint: %v", err)
	}
	if after.Size() > testLimit {
		t.Errorf("WAL is %d bytes after checkpoint, want <= %d (grew to %d before checkpointing)",
			after.Size(), testLimit, grown.Size())
	}
}
