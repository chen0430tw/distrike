//go:build linux || darwin

package scanner

import "syscall"

// getDeviceID returns the device ID (major/minor) of the filesystem hosting path.
// When a new filesystem is mounted over the same directory, this value changes,
// allowing the cache to detect stale entries.
func getDeviceID(path string) int64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return int64(st.Dev)
}
