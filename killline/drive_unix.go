//go:build linux || darwin

package killline

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/disk"
)

// pseudoFS contains filesystem types that should be skipped.
var pseudoFS = map[string]bool{
	"proc":       true,
	"sysfs":      true,
	"devfs":      true,
	"tmpfs":      true,
	"devtmpfs":   true,
	"overlay":    true,
	"squashfs":   true,
	"securityfs": true,
	"cgroup":     true,
	"cgroup2":    true,
	"pstore":     true,
	"debugfs":    true,
	"tracefs":    true,
	"hugetlbfs":  true,
	"mqueue":     true,
	"binfmt_misc": true,
	"configfs":   true,
	"fusectl":    true,
	"autofs":     true,
	"efivarfs":   true,
	"bpf":        true,
	"nsfs":       true,
	"ramfs":      true,
	"rpc_pipefs": true,
	"nfsd":       true,
	"devpts":     true,
}

// enumerateDrives lists all mount points with space info.
func enumerateDrives() ([]DriveInfo, error) {
	partitions, err := disk.Partitions(false) // false = only physical partitions
	if err != nil {
		return nil, fmt.Errorf("listing partitions: %w", err)
	}

	var drives []DriveInfo
	seen := make(map[string]bool) // deduplicate by mountpoint

	for _, p := range partitions {
		// Skip pseudo-filesystems
		if pseudoFS[p.Fstype] {
			continue
		}
		// Skip if already seen this mountpoint
		if seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true

		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			// Can't stat this mount — skip gracefully
			continue
		}

		drives = append(drives, DriveInfo{
			Path:       p.Mountpoint,
			Label:      "", // gopsutil doesn't expose volume labels on Unix
			FSType:     p.Fstype,
			TotalBytes: int64(usage.Total),
			FreeBytes:  int64(usage.Free),
			UsedBytes:  int64(usage.Used),
		})
	}

	return drives, nil
}
