//go:build windows

package scanner

import (
	"strings"

	"golang.org/x/sys/windows"
)

// isAdmin checks if the current process has an elevated token (Administrator).
func isAdmin() bool {
	var token windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	return token.IsElevated()
}

// getVolumeFS returns the filesystem type string for the volume containing path
// (e.g. "NTFS", "ReFS", "FAT32"). Returns "" on error.
func getVolumeFS(path string) string {
	var root string
	if len(path) >= 2 && path[1] == ':' {
		root = strings.ToUpper(string(path[0])) + ":\\"
	} else {
		return ""
	}

	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return ""
	}

	var fsNameBuf [256]uint16
	err = windows.GetVolumeInformation(
		rootPtr,
		nil, 0, nil, nil, nil,
		&fsNameBuf[0],
		uint32(len(fsNameBuf)),
	)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(fsNameBuf[:])
}

// isNTFS checks whether the volume containing the given path uses NTFS.
func isNTFS(path string) bool {
	return strings.EqualFold(getVolumeFS(path), "NTFS")
}

// isReFS checks whether the volume containing the given path uses ReFS.
func isReFS(path string) bool {
	return strings.EqualFold(getVolumeFS(path), "ReFS")
}
