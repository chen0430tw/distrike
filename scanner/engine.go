package scanner

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
	CollectAll     bool // When true, collect all directories (not just top-level). Used by hunt.
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
// Priority: MFT (Windows Admin + NTFS) > Cache (if fresh) > fastwalk
func SelectEngine(path string, engineHint string) Engine {
	// Phase 4: MFT engine selection
	// if engineHint == "mft" || (engineHint == "auto" && isAdmin() && isNTFS(path)):
	//     return &MFTEngine{}

	return &FastwalkEngine{}
}

// isAdmin checks if the current process has administrator/root privileges.
// Stub for Phase 4 MFT support.
func isAdmin() bool {
	// TODO: Phase 4 — implement platform-specific admin detection
	// Windows: use golang.org/x/sys/windows to check token elevation
	// Linux/macOS: check os.Getuid() == 0
	return false
}
