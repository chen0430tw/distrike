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

// isNTFS checks whether the volume containing the given path uses the NTFS filesystem.
func isNTFS(path string) bool {
	// Determine volume root path (e.g. "C:\")
	var root string
	if len(path) >= 2 && path[1] == ':' {
		root = strings.ToUpper(string(path[0])) + ":\\"
	} else {
		return false
	}

	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return false
	}

	var fsNameBuf [256]uint16

	err = windows.GetVolumeInformation(
		rootPtr,
		nil,   // volume name buffer
		0,     // volume name size
		nil,   // volume serial number
		nil,   // max component length
		nil,   // filesystem flags
		&fsNameBuf[0],
		uint32(len(fsNameBuf)),
	)
	if err != nil {
		return false
	}

	fsName := windows.UTF16ToString(fsNameBuf[:])
	return strings.EqualFold(fsName, "NTFS")
}
