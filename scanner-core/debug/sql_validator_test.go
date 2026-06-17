package debug

import (
	"testing"
)

func TestValidateQuery_ValidQueries(t *testing.T) {
	validQueries := []string{
		// SELECT queries
		"SELECT * FROM images",
		"select * from images",
		"  SELECT * FROM images  ",
		"SELECT id, name FROM images WHERE id = 1",
		"SELECT COUNT(*) FROM images",
		"SELECT * FROM images LIMIT 10",
		"SELECT * FROM images ORDER BY created_at DESC",
		"SELECT i.*, p.name FROM images i JOIN packages p ON i.id = p.image_id",
		"SELECT * FROM images WHERE digest = 'sha256:abc123'",
		"-- This is a comment\nSELECT * FROM images",
		"SELECT * FROM images -- comment at end",
		"SELECT * FROM images;",
		"SELECT * FROM images LIMIT 10;",
		"DESCRIBE images;",
		"EXPLAIN QUERY PLAN SELECT * FROM images;",
		"PRAGMA table_info(images);",
		// INSERT queries (now allowed)
		"INSERT INTO images VALUES (1, 'test')",
		"INSERT INTO test_table (col1, col2) VALUES ('a', 'b');",
		// UPDATE queries (now allowed)
		"UPDATE images SET name = 'test'",
		"UPDATE images SET status = 'completed' WHERE id = 1;",
		// DELETE queries (now allowed)
		"DELETE FROM images",
		"DELETE FROM images WHERE id = 1;",
		// Other DDL (now allowed)
		"DROP TABLE test_table",
		"CREATE TABLE test_table (id INT)",
		"ALTER TABLE images ADD COLUMN name VARCHAR(255)",
	}

	for _, query := range validQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := ValidateQuery(query)
			if !valid {
				t.Errorf("Expected query to be valid, got error: %v", err)
			}
		})
	}
}

func TestValidateQuery_EmptyQuery(t *testing.T) {
	emptyQueries := []string{
		"",
		"  ",
	}

	for _, query := range emptyQueries {
		t.Run("empty: "+query, func(t *testing.T) {
			valid, err := ValidateQuery(query)
			if valid {
				t.Errorf("Expected empty query to be invalid: %q", query)
			}
			if err == nil {
				t.Error("Expected error for empty query")
			}
		})
	}
}

func TestValidateQuery_MultipleStatements(t *testing.T) {
	// Queries with multiple statements should be blocked
	invalidQueries := []string{
		"SELECT * FROM images; DROP TABLE images;",
		"SELECT * FROM images; DROP TABLE images",
		"SELECT * FROM images;DROP TABLE images",
		"SELECT id FROM images; SELECT * FROM users",
		"INSERT INTO t1 VALUES (1); INSERT INTO t2 VALUES (2)",
		"UPDATE t1 SET a = 1; UPDATE t2 SET b = 2",
		"DELETE FROM t1; DELETE FROM t2",
		// Semicolons in string literals are also blocked (overly strict but acceptable for security)
		"SELECT * FROM images WHERE name = 'test;123'",
		"SELECT * FROM images WHERE desc = 'foo;bar;baz'",
	}

	for _, query := range invalidQueries {
		t.Run(query, func(t *testing.T) {
			valid, err := ValidateQuery(query)
			if valid {
				t.Errorf("Expected query with multiple statements to be invalid: %s", query)
			}
			if err == nil {
				t.Error("Expected error for query with multiple statements")
			}
			if err != nil && err.Error() != "multiple statements not allowed" {
				t.Errorf("Expected 'multiple statements not allowed' error, got: %v", err)
			}
		})
	}
}

func TestValidateQuery_TrailingSemicolon(t *testing.T) {
	// Single trailing semicolon should be allowed
	queries := []string{
		"SELECT * FROM images;",
		"INSERT INTO images VALUES (1, 'test');",
		"UPDATE images SET name = 'test';",
		"DELETE FROM images WHERE id = 1;",
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			valid, err := ValidateQuery(query)
			if !valid {
				t.Errorf("Expected query with trailing semicolon to be valid, got error: %v", err)
			}
		})
	}
}

// TestIsSelectQuery_BackwardCompatibility ensures IsSelectQuery still works as an alias
func TestIsSelectQuery_BackwardCompatibility(t *testing.T) {
	valid, err := IsSelectQuery("SELECT * FROM images")
	if !valid {
		t.Errorf("Expected IsSelectQuery to work as alias, got error: %v", err)
	}

	valid, err = IsSelectQuery("")
	if valid {
		t.Error("Expected IsSelectQuery to reject empty query")
	}
	if err == nil {
		t.Error("Expected error for empty query")
	}
}
