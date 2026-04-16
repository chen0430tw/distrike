package scanner

import (
	"os"
	"syscall"
	"time"
)

// getBirthtime returns the file creation time (birthtime) on Windows.
// Uses Win32FileAttributeData.CreationTime from the FileInfo syscall data.
func getBirthtime(info os.FileInfo) time.Time {
	if info == nil {
		return time.Time{}
	}
	sys, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return time.Time{}
	}
	// syscall.Filetime.Nanoseconds() converts Windows FILETIME (100ns ticks since
	// 1601-01-01) to nanoseconds since Unix epoch (1970-01-01).
	return time.Unix(0, sys.CreationTime.Nanoseconds())
}
