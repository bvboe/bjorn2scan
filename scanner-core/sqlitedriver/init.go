package sqlitedriver

import (
	// Import modernc.org/sqlite to register the SQLite driver
	// The driver registers itself in its init() function
	_ "modernc.org/sqlite"
)

// This package provides a single place to import the SQLite driver.
// It ensures consistent driver registration across the codebase.
