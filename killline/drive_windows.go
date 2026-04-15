//go:build windows

package killline

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enumerateDrives lists all Windows drive letters with space info.
func enumerateDrives() ([]DriveInfo, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, fmt.Errorf("GetLogicalDrives: %w", err)
	}

	var drives []DriveInfo
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i))
		rootPath := letter + `:\`

		// Check drive type — skip CDROM unless it has media
		rootPtr, _ := windows.UTF16PtrFromString(rootPath)
		driveType := windows.GetDriveType(rootPtr)
		if driveType == windows.DRIVE_NO_ROOT_DIR {
			continue
		}
		// Skip CDROM drives (usually no media or not interesting for disk analysis)
		if driveType == windows.DRIVE_CDROM {
			// Check if it actually has space info (media mounted)
			var totalBytes, freeBytes uint64
			err := windows.GetDiskFreeSpaceEx(rootPtr, nil, (*uint64)(unsafe.Pointer(&totalBytes)), (*uint64)(unsafe.Pointer(&freeBytes)))
			if err != nil {
				continue // No media — skip
			}
			if totalBytes == 0 {
				continue
			}
		}

		// Get disk space
		var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64
		err := windows.GetDiskFreeSpaceEx(
			rootPtr,
			(*uint64)(unsafe.Pointer(&freeBytesAvailable)),
			(*uint64)(unsafe.Pointer(&totalNumberOfBytes)),
			(*uint64)(unsafe.Pointer(&totalNumberOfFreeBytes)),
		)
		if err != nil {
			// Drive exists but can't get space (e.g. empty card reader) — skip
			continue
		}

		// Get volume information
		label, fsType := getVolumeInfo(rootPath)

		total := int64(totalNumberOfBytes)
		free := int64(totalNumberOfFreeBytes)
		removable := driveType == windows.DRIVE_REMOVABLE
		drives = append(drives, DriveInfo{
			Path:       rootPath,
			Label:      label,
			FSType:     fsType,
			TotalBytes: total,
			FreeBytes:  free,
			UsedBytes:  total - free,
			Removable:  removable,
		})
	}

	return drives, nil
}

// getVolumeInfo retrieves the volume label and filesystem type for a root path.
func getVolumeInfo(rootPath string) (label, fsType string) {
	rootPtr, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return "", ""
	}

	var volumeNameBuf [windows.MAX_PATH + 1]uint16
	var fsNameBuf [windows.MAX_PATH + 1]uint16
	var serialNumber, maxComponentLen, fsFlags uint32

	err = windows.GetVolumeInformation(
		rootPtr,
		&volumeNameBuf[0],
		uint32(len(volumeNameBuf)),
		&serialNumber,
		&maxComponentLen,
		&fsFlags,
		&fsNameBuf[0],
		uint32(len(fsNameBuf)),
	)
	if err != nil {
		return "", ""
	}

	label = windows.UTF16ToString(volumeNameBuf[:])
	fsType = windows.UTF16ToString(fsNameBuf[:])
	return label, fsType
}
