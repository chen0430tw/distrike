package scanner

import "time"

// Cache provides SQLite-backed scan result caching.
// Uses modernc.org/sqlite (pure Go, no CGO).
type Cache struct {
	dbPath string
	ttl    time.Duration
}

// NewCache creates a cache instance at the given path.
func NewCache(dbPath string, ttl time.Duration) *Cache {
	return &Cache{dbPath: dbPath, ttl: ttl}
}

// Load retrieves a cached scan result if fresh enough.
func (c *Cache) Load(path string) (*ScanResult, error) {
	// TODO: Phase 3
	return nil, nil
}

// Save stores a scan result in the cache.
func (c *Cache) Save(result *ScanResult) error {
	// TODO: Phase 3
	return nil
}

// Invalidate removes cached data for a path.
func (c *Cache) Invalidate(path string) error {
	// TODO: Phase 3
	return nil
}
