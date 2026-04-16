package scanner

import "time"

// Engine defines the interface for disk scanning backends.
type Engine interface {
	// Scan traverses the given path and returns directory entries.
	Scan(path string, opts ScanOptions) (*ScanResult, error)

	// Name returns the engine identifier (e.g., "fastwalk", "mft").
	Name() string
}

// ScanOptions controls scan behavior.
type ScanOptions struct {
	MaxDepth       int
	MinSize        int64
	TopN           int
	FollowSymlinks bool
	Workers        int
	Exclude        []string
	CollectAll     bool      // When true, collect all directories (not just top-level). Used by hunt.
	AfterTime      time.Time // Only count files modified after this time (zero = no filter).
	BeforeTime     time.Time // Only count files modified before this time (zero = no filter).
}

// ScanResult holds the output of a scan operation.
type ScanResult struct {
	RootPath     string     `json:"root_path"`
	TotalBytes   int64      `json:"total_bytes"`
	FreeBytes    int64      `json:"free_bytes"`
	UsedBytes    int64      `json:"used_bytes"`
	Entries      []DirEntry `json:"entries"`
	DeniedPaths  []string   `json:"denied_paths,omitempty"`
	ScanCoverage float64    `json:"scan_coverage"`
	DurationMs   int64      `json:"scan_duration_ms"`
	EngineName   string     `json:"scan_engine"`
}

// SelectEngine picks the best available engine for the given path.
// Returns the engine and an optional note to display to the user.
// Priority: MFT (Windows Admin + NTFS) > fastwalk
// ReFS volumes always use fastwalk — ReFS has no MFT or USN Journal.
func SelectEngine(path string, engineHint string) (Engine, string) {
	if isReFS(path) {
		return &FastwalkEngine{}, "ReFS volume detected — using fastwalk (ReFS has no MFT or USN Journal)"
	}
	if engineHint == "mft" || (engineHint == "auto" && isAdmin() && isNTFS(path)) {
		return &MFTEngine{}, ""
	}
	return &FastwalkEngine{}, ""
}
