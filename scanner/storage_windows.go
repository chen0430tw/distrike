//go:build windows

package scanner

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

// physicalDiskInfo matches the JSON output of Get-PhysicalDisk.
type physicalDiskInfo struct {
	DeviceID     string `json:"DeviceID"`
	MediaType    int    `json:"MediaType"`
	FriendlyName string `json:"FriendlyName"`
}

// partitionDiskMapping maps a drive letter to a physical disk number.
type partitionDiskMapping struct {
	DriveLetter string `json:"DriveLetter"`
	DiskNumber  int    `json:"DiskNumber"`
}

// WMI MediaType constants
const (
	mediaTypeUnspecified = 0
	mediaTypeHDD         = 3
	mediaTypeSSD         = 4
	mediaTypeSCM         = 5 // Storage Class Memory (treat as SSD)
)

// detectStorageType determines whether the path resides on SSD or HDD.
// It uses PowerShell WMI queries to map the drive letter to a physical disk.
// Falls back to StorageUnknown on any error.
func detectStorageType(path string) StorageType {
	abs, err := filepath.Abs(path)
	if err != nil {
		return StorageUnknown
	}

	// Extract drive letter (e.g., "C" from "C:\Users\...")
	driveLetter := extractDriveLetter(abs)
	if driveLetter == "" {
		return StorageUnknown
	}

	// Strategy 1: Map drive letter → disk number → media type via partitions
	if st := detectViaDriveMapping(driveLetter); st != StorageUnknown {
		return st
	}

	// Strategy 2: Query all physical disks, if only one exists use its type
	if st := detectViaSingleDisk(); st != StorageUnknown {
		return st
	}

	return StorageUnknown
}

// detectViaDriveMapping uses Get-Partition and Get-PhysicalDisk to map
// a specific drive letter to its physical disk media type.
func detectViaDriveMapping(driveLetter string) StorageType {
	// Get partition → disk number mapping
	psCmd := `Get-Partition | Where-Object { $_.DriveLetter -ne [char]0 } | ` +
		`Select-Object @{N='DriveLetter';E={[string]$_.DriveLetter}}, DiskNumber | ConvertTo-Json`

	out, err := runPowerShell(psCmd)
	if err != nil {
		return StorageUnknown
	}

	mappings, err := parsePartitionMappings(out)
	if err != nil {
		return StorageUnknown
	}

	// Find which disk number this drive letter belongs to
	diskNum := -1
	for _, m := range mappings {
		if strings.EqualFold(m.DriveLetter, driveLetter) {
			diskNum = m.DiskNumber
			break
		}
	}
	if diskNum < 0 {
		return StorageUnknown
	}

	// Get physical disk info
	psCmd2 := `Get-PhysicalDisk | Select-Object DeviceID, MediaType, FriendlyName | ConvertTo-Json`
	out2, err := runPowerShell(psCmd2)
	if err != nil {
		return StorageUnknown
	}

	disks, err := parsePhysicalDisks(out2)
	if err != nil {
		return StorageUnknown
	}

	target := itoa(diskNum)
	for _, d := range disks {
		if d.DeviceID == target {
			return mediaTypeToStorage(d.MediaType)
		}
	}

	return StorageUnknown
}

// detectViaSingleDisk is a fallback: if there's exactly one physical disk,
// return its type regardless of partition mapping.
func detectViaSingleDisk() StorageType {
	psCmd := `Get-PhysicalDisk | Select-Object DeviceID, MediaType, FriendlyName | ConvertTo-Json`
	out, err := runPowerShell(psCmd)
	if err != nil {
		return StorageUnknown
	}

	disks, err := parsePhysicalDisks(out)
	if err != nil || len(disks) != 1 {
		return StorageUnknown
	}

	return mediaTypeToStorage(disks[0].MediaType)
}

func runPowerShell(command string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", command)
	return cmd.Output()
}

func extractDriveLetter(absPath string) string {
	if len(absPath) >= 2 && absPath[1] == ':' && unicode.IsLetter(rune(absPath[0])) {
		return strings.ToUpper(string(absPath[0]))
	}
	return ""
}

func parsePhysicalDisks(data []byte) ([]physicalDiskInfo, error) {
	data = trimBOM(data)
	// PowerShell returns a single object (not array) when there's only one disk
	var disks []physicalDiskInfo
	if err := json.Unmarshal(data, &disks); err != nil {
		var single physicalDiskInfo
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err
		}
		disks = []physicalDiskInfo{single}
	}
	return disks, nil
}

func parsePartitionMappings(data []byte) ([]partitionDiskMapping, error) {
	data = trimBOM(data)
	var mappings []partitionDiskMapping
	if err := json.Unmarshal(data, &mappings); err != nil {
		var single partitionDiskMapping
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, err
		}
		mappings = []partitionDiskMapping{single}
	}
	return mappings, nil
}

func trimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return data
}

func mediaTypeToStorage(mediaType int) StorageType {
	switch mediaType {
	case mediaTypeSSD, mediaTypeSCM:
		return StorageSSD
	case mediaTypeHDD:
		return StorageHDD
	default:
		return StorageUnknown
	}
}

// strings.Itoa replacement to avoid importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
