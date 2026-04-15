package killline

// DriveInfo holds basic information about a drive or mount point.
type DriveInfo struct {
	Path       string `json:"path"`
	Label      string `json:"label,omitempty"`
	FSType     string `json:"fs_type"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	Removable  bool   `json:"removable"`
}

// EnumerateDrives returns all mounted drives/partitions.
func EnumerateDrives() ([]DriveInfo, error) {
	return enumerateDrives()
}

// enumerateDrives is implemented per-platform:
// drive_windows.go, drive_darwin.go, drive_unix.go
