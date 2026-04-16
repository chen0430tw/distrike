package scanner

import "time"

// DirEntry represents a file or directory with size information.
type DirEntry struct {
	Path         string    `json:"path"`
	SizeBytes    int64     `json:"size_bytes"`
	IsDir        bool      `json:"is_dir"`
	ChildCount   int       `json:"children_count,omitempty"`
	LastModified time.Time `json:"last_modified"`
	// CreatedAt holds the most recent birthtime among files accumulated into this entry.
	// Zero on platforms that don't expose birthtime (Linux without statx).
	CreatedAt time.Time `json:"created_at,omitempty"`
}
