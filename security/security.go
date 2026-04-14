package security

import (
	"os/exec"
	"runtime"
	"strings"
)

// EncryptionState represents the state of an encrypted volume.
type EncryptionState struct {
	Drive  string `json:"drive"`
	Method string `json:"method"` // "BitLocker", "FileVault", "LUKS", "none"
	State  string `json:"state"`  // "unlocked", "locked", "unknown"
}

// DeniedPath records a path that could not be scanned due to permissions.
type DeniedPath struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// AccessReport summarizes permission issues during a scan.
type AccessReport struct {
	Coverage         float64           `json:"scan_coverage"`    // 0.0 - 1.0
	DeniedPaths      []DeniedPath      `json:"denied_paths,omitempty"`
	EstimatedMissing int64             `json:"denied_estimated_bytes,omitempty"`
	Encryption       []EncryptionState `json:"encryption_status,omitempty"`
}

// DetectEncryption checks all drives for encryption status.
func DetectEncryption() ([]EncryptionState, error) {
	switch runtime.GOOS {
	case "windows":
		return detectBitLocker()
	case "darwin":
		return detectFileVault()
	case "linux":
		return detectLUKS()
	default:
		return nil, nil
	}
}

// detectBitLocker runs manage-bde -status and parses the output.
func detectBitLocker() ([]EncryptionState, error) {
	out, err := exec.Command("manage-bde", "-status").Output()
	if err != nil {
		// manage-bde not available (non-Pro Windows or not admin).
		// Return unknown state for system drive.
		return []EncryptionState{
			{Drive: "C:", Method: "unknown", State: "unknown"},
		}, nil
	}

	var states []EncryptionState
	output := string(out)
	sections := strings.Split(output, "Volume ")

	for _, section := range sections[1:] { // Skip the header before first "Volume"
		lines := strings.Split(section, "\n")
		if len(lines) == 0 {
			continue
		}

		// First line contains the drive letter, e.g., "C: [OSDisk]"
		driveLine := strings.TrimSpace(lines[0])
		drive := ""
		if len(driveLine) >= 2 && driveLine[1] == ':' {
			drive = driveLine[:2]
		} else {
			continue
		}

		es := EncryptionState{
			Drive:  drive,
			Method: "none",
			State:  "unknown",
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)

			// Check protection status.
			if strings.HasPrefix(line, "Protection Status:") || strings.HasPrefix(line, "Conversion Status:") {
				value := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				lower := strings.ToLower(value)
				if strings.Contains(lower, "on") || strings.Contains(lower, "fully encrypted") {
					es.Method = "BitLocker"
					es.State = "unlocked"
				} else if strings.Contains(lower, "off") || strings.Contains(lower, "fully decrypted") {
					es.Method = "none"
					es.State = "unlocked"
				}
			}

			// Check lock status.
			if strings.HasPrefix(line, "Lock Status:") {
				value := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				lower := strings.ToLower(value)
				if strings.Contains(lower, "locked") {
					es.State = "locked"
				} else if strings.Contains(lower, "unlocked") {
					es.State = "unlocked"
				}
			}

			// Check encryption method.
			if strings.HasPrefix(line, "Encryption Method:") {
				value := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
				if !strings.EqualFold(value, "None") && value != "" {
					es.Method = "BitLocker"
				}
			}
		}

		states = append(states, es)
	}

	if len(states) == 0 {
		return []EncryptionState{
			{Drive: "C:", Method: "none", State: "unknown"},
		}, nil
	}

	return states, nil
}

// detectFileVault runs fdesetup status on macOS.
func detectFileVault() ([]EncryptionState, error) {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return []EncryptionState{
			{Drive: "/", Method: "unknown", State: "unknown"},
		}, nil
	}

	output := strings.TrimSpace(string(out))
	es := EncryptionState{
		Drive:  "/",
		Method: "none",
		State:  "unknown",
	}

	if strings.Contains(output, "FileVault is On") {
		es.Method = "FileVault"
		es.State = "unlocked"
	} else if strings.Contains(output, "FileVault is Off") {
		es.Method = "none"
		es.State = "unlocked"
	}

	return []EncryptionState{es}, nil
}

// detectLUKS checks for LUKS-encrypted partitions on Linux.
func detectLUKS() ([]EncryptionState, error) {
	out, err := exec.Command("lsblk", "-o", "NAME,FSTYPE,TYPE", "--noheadings").Output()
	if err != nil {
		return []EncryptionState{
			{Drive: "/", Method: "unknown", State: "unknown"},
		}, nil
	}

	var states []EncryptionState
	hasCrypt := false

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		// Strip tree-drawing characters from lsblk output.
		name = strings.TrimLeft(name, "├─└│ ")

		fstype := ""
		devType := ""
		if len(fields) >= 2 {
			fstype = fields[1]
		}
		if len(fields) >= 3 {
			devType = fields[2]
		}

		if fstype == "crypto_LUKS" || devType == "crypt" || strings.Contains(fstype, "crypt") {
			hasCrypt = true
			states = append(states, EncryptionState{
				Drive:  "/dev/" + name,
				Method: "LUKS",
				State:  "unlocked", // If we can see it via lsblk, it's unlocked.
			})
		}
	}

	if !hasCrypt {
		states = append(states, EncryptionState{
			Drive:  "/",
			Method: "none",
			State:  "unlocked",
		})
	}

	return states, nil
}

// Policy defines how to handle access-denied errors.
type Policy int

const (
	PolicySkip Policy = iota // Skip and record
	PolicyWarn               // Skip, record, and warn in output
)
