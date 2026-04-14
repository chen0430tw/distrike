package scanner

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Cache provides SQLite-backed scan result caching.
// Uses modernc.org/sqlite (pure Go, no CGO).
type Cache struct {
	dbPath string
	ttl    time.Duration
	db     *sql.DB
}

// NewCache creates a cache instance at the given path and opens the database.
func NewCache(dbPath string, ttl time.Duration) (*Cache, error) {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening cache database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	c := &Cache{dbPath: dbPath, ttl: ttl, db: db}
	if err := c.InitDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing cache tables: %w", err)
	}

	return c, nil
}

// InitDB creates the cache tables if they do not exist.
func (c *Cache) InitDB() error {
	const schema = `
	CREATE TABLE IF NOT EXISTS scan_cache (
		path          TEXT    NOT NULL,
		root_path     TEXT    NOT NULL,
		size_bytes    INTEGER NOT NULL,
		children      INTEGER NOT NULL DEFAULT 0,
		kind          TEXT    NOT NULL DEFAULT '',
		is_dir        BOOLEAN NOT NULL DEFAULT 0,
		last_modified INTEGER NOT NULL DEFAULT 0,
		scan_time     INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (root_path, path)
	);

	CREATE INDEX IF NOT EXISTS idx_scan_cache_root ON scan_cache(root_path);

	CREATE TABLE IF NOT EXISTS scan_meta (
		root_path   TEXT    PRIMARY KEY,
		total_bytes INTEGER NOT NULL DEFAULT 0,
		free_bytes  INTEGER NOT NULL DEFAULT 0,
		used_bytes  INTEGER NOT NULL DEFAULT 0,
		engine      TEXT    NOT NULL DEFAULT '',
		duration_ms INTEGER NOT NULL DEFAULT 0,
		coverage    REAL    NOT NULL DEFAULT 0,
		scan_time   INTEGER NOT NULL DEFAULT 0
	);
	`
	_, err := c.db.Exec(schema)
	return err
}

// Close closes the underlying database connection.
func (c *Cache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// Load retrieves a cached scan result if fresh enough (scan_time + ttl > now).
// Returns nil, nil if no valid cache exists.
func (c *Cache) Load(rootPath string) (*ScanResult, error) {
	now := time.Now().Unix()

	// Check scan_meta for freshness
	var (
		totalBytes int64
		freeBytes  int64
		usedBytes  int64
		engine     string
		durationMs int64
		coverage   float64
		scanTime   int64
	)
	err := c.db.QueryRow(
		`SELECT total_bytes, free_bytes, used_bytes, engine, duration_ms, coverage, scan_time
		 FROM scan_meta WHERE root_path = ?`, rootPath,
	).Scan(&totalBytes, &freeBytes, &usedBytes, &engine, &durationMs, &coverage, &scanTime)

	if err == sql.ErrNoRows {
		return nil, nil // no cache
	}
	if err != nil {
		return nil, fmt.Errorf("querying scan_meta: %w", err)
	}

	// Check TTL
	if scanTime+int64(c.ttl.Seconds()) <= now {
		return nil, nil // expired
	}

	// Load entries
	rows, err := c.db.Query(
		`SELECT path, size_bytes, children, kind, is_dir, last_modified
		 FROM scan_cache WHERE root_path = ?`, rootPath,
	)
	if err != nil {
		return nil, fmt.Errorf("querying scan_cache: %w", err)
	}
	defer rows.Close()

	var entries []DirEntry
	for rows.Next() {
		var (
			path         string
			sizeBytes    int64
			children     int
			kind         string
			isDir        bool
			lastModified int64
		)
		if err := rows.Scan(&path, &sizeBytes, &children, &kind, &isDir, &lastModified); err != nil {
			return nil, fmt.Errorf("scanning cache row: %w", err)
		}
		_ = kind // DirEntry doesn't have Kind field; reserved for future use
		entries = append(entries, DirEntry{
			Path:         path,
			SizeBytes:    sizeBytes,
			IsDir:        isDir,
			ChildCount:   children,
			LastModified: time.Unix(lastModified, 0),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating cache rows: %w", err)
	}

	return &ScanResult{
		RootPath:     rootPath,
		TotalBytes:   totalBytes,
		FreeBytes:    freeBytes,
		UsedBytes:    usedBytes,
		Entries:      entries,
		ScanCoverage: coverage,
		DurationMs:   durationMs,
		EngineName:   engine + " (cached)",
	}, nil
}

// Save stores a scan result in the cache, upserting scan_meta and all entries.
func (c *Cache) Save(result *ScanResult) error {
	now := time.Now().Unix()

	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	// Upsert scan_meta
	_, err = tx.Exec(`
		INSERT INTO scan_meta (root_path, total_bytes, free_bytes, used_bytes, engine, duration_ms, coverage, scan_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(root_path) DO UPDATE SET
			total_bytes = excluded.total_bytes,
			free_bytes  = excluded.free_bytes,
			used_bytes  = excluded.used_bytes,
			engine      = excluded.engine,
			duration_ms = excluded.duration_ms,
			coverage    = excluded.coverage,
			scan_time   = excluded.scan_time
	`, result.RootPath, result.TotalBytes, result.FreeBytes, result.UsedBytes,
		result.EngineName, result.DurationMs, result.ScanCoverage, now)
	if err != nil {
		return fmt.Errorf("upserting scan_meta: %w", err)
	}

	// Delete old entries for this root path, then insert new ones
	_, err = tx.Exec(`DELETE FROM scan_cache WHERE root_path = ?`, result.RootPath)
	if err != nil {
		return fmt.Errorf("deleting old cache entries: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO scan_cache (path, root_path, size_bytes, children, kind, is_dir, last_modified, scan_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer stmt.Close()

	for _, e := range result.Entries {
		_, err = stmt.Exec(
			e.Path, result.RootPath, e.SizeBytes, e.ChildCount, "",
			e.IsDir, e.LastModified.Unix(), now,
		)
		if err != nil {
			return fmt.Errorf("inserting cache entry %q: %w", e.Path, err)
		}
	}

	return tx.Commit()
}

// Invalidate removes all cached data for a root path.
func (c *Cache) Invalidate(rootPath string) error {
	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM scan_cache WHERE root_path = ?`, rootPath); err != nil {
		return fmt.Errorf("deleting cache entries: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM scan_meta WHERE root_path = ?`, rootPath); err != nil {
		return fmt.Errorf("deleting meta entry: %w", err)
	}

	return tx.Commit()
}
