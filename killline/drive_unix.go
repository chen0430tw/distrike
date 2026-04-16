//go:build linux || darwin

package killline

import (
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
)

// pseudoFS contains filesystem types that are always noise — never real storage.
var pseudoFS = map[string]bool{
	"proc":        true,
	"sysfs":       true,
	"devfs":       true,
	"devtmpfs":    true,
	"securityfs":  true,
	"cgroup":      true,
	"cgroup2":     true,
	"pstore":      true,
	"debugfs":     true,
	"tracefs":     true,
	"hugetlbfs":   true,
	"mqueue":      true,
	"binfmt_misc": true,
	"configfs":    true,
	"fusectl":     true,
	"autofs":      true,
	"efivarfs":    true,
	"bpf":         true,
	"nsfs":        true,
	"rpc_pipefs":  true,
	"nfsd":        true,
	"devpts":      true,
	"rootfs":      true, // WSL/initrd initial root namespace
}

// systemMountPrefixes are path prefixes that are always system-internal
// regardless of filesystem type.
var systemMountPrefixes = []string{
	"/run", "/dev", "/sys", "/proc",
	"/tmp",          // system temporary mounts (X11 sockets, lock dirs, etc.)
	"/snap",         // snap package mounts
	"/mnt/wslg",     // WSL GUI subsystem internals
	"/mnt/wsl",      // WSL shared memory fs (both exact /mnt/wsl and sub-paths /mnt/wsl/*)
	"/usr/lib/wsl",
}

// isSystemMount returns true if this mount should be hidden from the user.
func isSystemMount(mountpoint, fstype string) bool {
	if pseudoFS[fstype] {
		return true
	}
	if fstype == "squashfs" { // snap packages
		return true
	}
	// Check known system path prefixes — applies to ALL filesystem types.
	for _, prefix := range systemMountPrefixes {
		if mountpoint == prefix || strings.HasPrefix(mountpoint, prefix+"/") {
			return true
		}
	}
	// overlay at non-user paths (Docker layers, WSL overlays, etc.)
	if fstype == "overlay" && !strings.HasPrefix(mountpoint, "/mnt/") {
		return true
	}
	return false
}

// isUserVisible returns true if a mountpoint is explicitly user-created
// (e.g. under /mnt/ but NOT under a known system prefix).
func isUserVisible(mountpoint, fstype string) bool {
	return strings.HasPrefix(mountpoint, "/mnt/") && !isSystemMount(mountpoint, fstype)
}

// enumerateDrives lists all mount points with space info.
func enumerateDrives() ([]DriveInfo, error) {
	// Use all=true to include tmpfs and other non-physical mounts.
	// We apply our own isSystemMount filter instead of relying on gopsutil's default.
	partitions, err := disk.Partitions(true)
	if err != nil {
		return nil, fmt.Errorf("listing partitions: %w", err)
	}

	var drives []DriveInfo
	seenMount := make(map[string]bool)  // dedup by mountpoint
	seenDevice := make(map[string]bool) // dedup by device — same storage shown only once

	for _, p := range partitions {
		if isSystemMount(p.Mountpoint, p.Fstype) {
			continue
		}
		if seenMount[p.Mountpoint] {
			continue
		}

		// Device dedup: if we already showed this physical device, only show
		// additional mounts when they are explicitly user-visible (/mnt/* non-system).
		// Prevents WSL from listing /, /mnt/wslg/distro, /snap as separate drives
		// when they all live on the same ext4 partition.
		if p.Device != "" && seenDevice[p.Device] && !isUserVisible(p.Mountpoint, p.Fstype) {
			continue
		}

		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		// Skip zero-capacity mounts (uninitialized tmpfs, empty ramfs, etc.)
		if usage.Total == 0 {
			continue
		}

		seenMount[p.Mountpoint] = true
		if p.Device != "" {
			seenDevice[p.Device] = true
		}

		drives = append(drives, DriveInfo{
			Path:       p.Mountpoint,
			Label:      "",
			FSType:     p.Fstype,
			TotalBytes: int64(usage.Total),
			FreeBytes:  int64(usage.Free),
			UsedBytes:  int64(usage.Used),
		})
	}

	return drives, nil
}
