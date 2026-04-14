package vdisk

import (
	"path/filepath"
	"strings"

	"distrike/scanner"
)

// VDiskType classifies the virtual disk format.
type VDiskType string

const (
	TypeVHDX  VDiskType = "vhdx"
	TypeVMDK  VDiskType = "vmdk"
	TypeVDI   VDiskType = "vdi"
	TypeQCOW2 VDiskType = "qcow2"
)

// VDiskInfo holds information about a detected virtual disk file.
type VDiskInfo struct {
	Path                  string    `json:"path"`
	SizeBytes             int64     `json:"size_bytes"`
	Type                  VDiskType `json:"type"`
	CompactionSuggestion  string    `json:"compaction_suggestion"`
	PotentialSavingsBytes int64     `json:"potential_savings_bytes,omitempty"`
}

// knownExtensions maps file extensions to virtual disk types.
var knownExtensions = map[string]VDiskType{
	".vhdx":  TypeVHDX,
	".vmdk":  TypeVMDK,
	".vdi":   TypeVDI,
	".qcow2": TypeQCOW2,
}

// Detect scans a list of directory entries for virtual disk files.
func Detect(entries []scanner.DirEntry) []VDiskInfo {
	var results []VDiskInfo

	for _, entry := range entries {
		if entry.IsDir {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Path))
		vtype, ok := knownExtensions[ext]
		if !ok {
			continue
		}

		info := VDiskInfo{
			Path:      entry.Path,
			SizeBytes: entry.SizeBytes,
			Type:      vtype,
		}

		info.CompactionSuggestion = compactionHint(vtype)
		// Estimate 10-30% savings from compaction for dynamically expanding disks.
		info.PotentialSavingsBytes = entry.SizeBytes / 5 // ~20% estimate

		results = append(results, info)
	}

	return results
}

// compactionHint returns a platform-appropriate compaction command or hint.
func compactionHint(vtype VDiskType) string {
	switch vtype {
	case TypeVHDX:
		return "Run fstrim inside VM, then: powershell Mount-VHD -Path <file> -ReadOnly; Optimize-VHD -Path <file> -Mode Full; Dismount-VHD -Path <file>"
	case TypeVMDK:
		return "Run vmware-vdiskmanager -k <file> or use VMware's disk shrink utility"
	case TypeVDI:
		return "Run VBoxManage modifymedium disk <file> --compact after zeroing free space inside VM"
	case TypeQCOW2:
		return "Run qemu-img convert -O qcow2 -c <input> <output> for compression, or virt-sparsify for in-place"
	default:
		return "Consider compacting or compressing this virtual disk"
	}
}

// IsVDiskFile checks if a file path matches a known virtual disk extension.
func IsVDiskFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := knownExtensions[ext]
	return ok
}
