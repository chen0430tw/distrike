//go:build linux || darwin

package scanner

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// detectStorageType determines whether the path resides on SSD or HDD.
// Linux: reads /sys/block/<dev>/queue/rotational (0=SSD, 1=HDD).
// macOS: uses diskutil info to check SolidState key.
func detectStorageType(path string) StorageType {
	abs, err := filepath.Abs(path)
	if err != nil {
		return StorageUnknown
	}

	switch runtime.GOOS {
	case "linux":
		return detectLinux(abs)
	case "darwin":
		return detectDarwin(abs)
	default:
		return StorageUnknown
	}
}

// detectLinux maps the path to a block device via /proc/mounts, then reads
// /sys/block/<dev>/queue/rotational to determine storage type.
func detectLinux(absPath string) StorageType {
	dev := findBlockDevice(absPath)
	if dev == "" {
		return StorageUnknown
	}

	// Strip partition number to get base device: /dev/sda1 → sda, /dev/nvme0n1p1 → nvme0n1
	baseDev := baseBlockDevice(dev)
	if baseDev == "" {
		return StorageUnknown
	}

	// Read rotational flag
	rotPath := "/sys/block/" + baseDev + "/queue/rotational"
	data, err := os.ReadFile(rotPath)
	if err != nil {
		return StorageUnknown
	}

	val := strings.TrimSpace(string(data))
	switch val {
	case "0":
		return StorageSSD
	case "1":
		return StorageHDD
	default:
		return StorageUnknown
	}
}

// findBlockDevice looks up the mount point for the given path in /proc/mounts
// and returns the device path (e.g., /dev/sda1).
func findBlockDevice(absPath string) string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return ""
	}
	defer f.Close()

	var bestMount string
	var bestDev string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		dev, mount := fields[0], fields[1]

		// Skip virtual filesystems
		if !strings.HasPrefix(dev, "/dev/") {
			continue
		}

		// Find the longest mount point prefix that matches our path
		if strings.HasPrefix(absPath, mount) && len(mount) > len(bestMount) {
			bestMount = mount
			bestDev = dev
		}
	}

	return bestDev
}

// baseBlockDevice strips the partition suffix from a device name.
// /dev/sda1 → sda, /dev/nvme0n1p1 → nvme0n1, /dev/vda2 → vda
func baseBlockDevice(devPath string) string {
	// Strip /dev/ prefix
	name := filepath.Base(devPath)

	// NVMe: nvme0n1p1 → nvme0n1
	if strings.HasPrefix(name, "nvme") {
		if idx := strings.LastIndex(name, "p"); idx > 4 {
			// Verify everything after 'p' is digits
			suffix := name[idx+1:]
			if isDigits(suffix) {
				return name[:idx]
			}
		}
		return name
	}

	// Standard block devices: sda1 → sda, vda2 → vda, xvda1 → xvda
	// Strip trailing digits
	i := len(name) - 1
	for i >= 0 && name[i] >= '0' && name[i] <= '9' {
		i--
	}
	if i >= 0 && i < len(name)-1 {
		return name[:i+1]
	}
	return name
}

// detectDarwin uses diskutil info to check if the disk is solid state.
func detectDarwin(absPath string) StorageType {
	// Find mount point for this path using df
	dev := findDarwinDevice(absPath)
	if dev == "" {
		return StorageUnknown
	}

	// Query diskutil for the device
	out, err := exec.Command("diskutil", "info", dev).Output()
	if err != nil {
		return StorageUnknown
	}

	// Look for "Solid State: Yes/No"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Solid State:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Solid State:"))
			switch strings.ToLower(val) {
			case "yes":
				return StorageSSD
			case "no":
				return StorageHDD
			}
		}
	}

	return StorageUnknown
}

// findDarwinDevice uses df to find the device for a path.
func findDarwinDevice(absPath string) string {
	out, err := exec.Command("df", absPath).Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return ""
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 1 {
		return ""
	}

	dev := fields[0]
	if strings.HasPrefix(dev, "/dev/") {
		return dev
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
