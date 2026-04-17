//go:build windows

package scanner

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// getDeviceID returns a volume-based identifier for the filesystem hosting path.
// Uses GetVolumeInformation to get the volume serial number.
func getDeviceID(path string) int64 {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0
	}
	// Ensure we have a root path (e.g. "C:\")
	root := filepath.VolumeName(abs)
	if root == "" {
		return 0
	}
	rootPath := root + `\`
	rootPtr, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return 0
	}
	var serial uint32
	err = windows.GetVolumeInformation(
		rootPtr,
		nil, 0,
		&serial,
		nil, nil,
		(*uint16)(unsafe.Pointer(nil)), 0,
	)
	if err != nil {
		// Fall back to drive letter index
		letter := strings.ToUpper(root)
		if len(letter) > 0 {
			return int64(letter[0])
		}
		return 0
	}
	// Combine drive letter and serial to distinguish volumes on the same letter
	letter := int64(strings.ToUpper(root)[0])
	return letter<<32 | int64(serial)
}
