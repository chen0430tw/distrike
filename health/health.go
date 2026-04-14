package health

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Alert represents a storage health warning.
type Alert struct {
	Level   string `json:"level"`   // "yellow", "red"
	Kind    string `json:"kind"`    // "smart_warning", "capacity_anomaly", "bad_sectors", "wear_level", "fs_error"
	Message string `json:"message"`
}

// DeviceHealth holds health information for a storage device.
type DeviceHealth struct {
	Device    string  `json:"device"`
	Type      string  `json:"type"` // "ssd", "hdd", "usb", "sdcard", "network"
	Model     string  `json:"model"`
	Removable bool    `json:"removable"`
	Alerts    []Alert `json:"alerts,omitempty"`
	SMART     *SMART  `json:"smart,omitempty"`
}

// SMART holds S.M.A.R.T. data for a drive.
type SMART struct {
	Status             string `json:"status"` // "PASSED", "FAILED"
	ReallocatedSectors int    `json:"reallocated_sectors"`
	PendingSectors     int    `json:"pending_sectors"`
	WearLevelPct       int    `json:"wear_level_pct,omitempty"` // SSD only, 100=new
}

// HealthOptions controls which checks to run.
type HealthOptions struct {
	SMARTEnabled      bool
	CapacityAnomaly   bool
	RemovableOnly     bool
	BadSectorWarn     int
	BadSectorCritical int
	WearLevelWarn     int
	WearLevelCritical int
}

// Check performs health checks on all detected storage devices.
func Check(opts HealthOptions) ([]DeviceHealth, error) {
	var devices []DeviceHealth

	switch runtime.GOOS {
	case "windows":
		devices = checkWindows(opts)
	case "linux":
		devices = checkLinux(opts)
	case "darwin":
		devices = checkDarwin(opts)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return devices, nil
}

// checkWindows uses wmic to get disk status on Windows.
func checkWindows(opts HealthOptions) []DeviceHealth {
	var devices []DeviceHealth

	// Try wmic to list disk drives and their status.
	out, err := exec.Command("wmic", "diskdrive", "get",
		"DeviceID,Model,MediaType,Status,Size", "/format:csv").Output()
	if err != nil {
		// wmic not available; try smartctl as fallback.
		return checkWithSmartctl(opts)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 6 {
			continue
		}

		// CSV fields: Node, DeviceID, MediaType, Model, Size, Status
		deviceID := strings.TrimSpace(fields[1])
		mediaType := strings.TrimSpace(fields[2])
		model := strings.TrimSpace(fields[3])
		status := strings.TrimSpace(fields[5])

		devType := classifyMediaType(mediaType)

		dh := DeviceHealth{
			Device: deviceID,
			Type:   devType,
			Model:  model,
		}

		if opts.SMARTEnabled {
			dh.SMART = &SMART{Status: status}
			if !strings.EqualFold(status, "OK") {
				dh.Alerts = append(dh.Alerts, Alert{
					Level:   "red",
					Kind:    "smart_warning",
					Message: fmt.Sprintf("Disk %s reports status: %s", deviceID, status),
				})
			}
		}

		devices = append(devices, dh)
	}

	// Supplement with smartctl if available and SMART is enabled.
	if opts.SMARTEnabled {
		devices = supplementSmartctl(devices, opts)
	}

	if len(devices) == 0 {
		return checkWithSmartctl(opts)
	}
	return devices
}

// checkLinux uses smartctl if available.
func checkLinux(opts HealthOptions) []DeviceHealth {
	return checkWithSmartctl(opts)
}

// checkDarwin uses smartctl if available.
func checkDarwin(opts HealthOptions) []DeviceHealth {
	return checkWithSmartctl(opts)
}

// checkWithSmartctl attempts to use smartctl for health checks.
func checkWithSmartctl(opts HealthOptions) []DeviceHealth {
	smartctlPath, err := exec.LookPath("smartctl")
	if err != nil {
		// smartctl not found; skip gracefully.
		return nil
	}

	var devices []DeviceHealth

	// Scan for devices.
	out, err := exec.Command(smartctlPath, "--scan").Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// First field is device path, e.g., "/dev/sda"
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		devPath := fields[0]

		dh := checkSingleDevice(smartctlPath, devPath, opts)
		if dh != nil {
			devices = append(devices, *dh)
		}
	}

	return devices
}

// checkSingleDevice runs smartctl -H on a single device.
func checkSingleDevice(smartctlPath, devPath string, opts HealthOptions) *DeviceHealth {
	dh := &DeviceHealth{
		Device: devPath,
		Type:   "unknown",
	}

	// Get device info.
	infoOut, err := exec.Command(smartctlPath, "-i", devPath).Output()
	if err == nil {
		info := string(infoOut)
		for _, line := range strings.Split(info, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Device Model:") || strings.HasPrefix(line, "Model Number:") {
				dh.Model = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			}
			if strings.Contains(line, "Solid State") || strings.Contains(line, "SSD") {
				dh.Type = "ssd"
			} else if strings.Contains(line, "Rotating") || strings.Contains(line, "HDD") {
				dh.Type = "hdd"
			}
		}
	}

	if !opts.SMARTEnabled {
		return dh
	}

	// Run health check.
	healthOut, err := exec.Command(smartctlPath, "-H", devPath).Output()
	if err != nil {
		// smartctl may exit non-zero for SMART warnings; still parse output.
		if exitErr, ok := err.(*exec.ExitError); ok {
			healthOut = exitErr.Stderr
			if len(healthOut) == 0 {
				healthOut = exitErr.Stderr
			}
		}
	}

	if len(healthOut) > 0 {
		healthStr := string(healthOut)
		smart := &SMART{Status: "UNKNOWN"}

		if strings.Contains(healthStr, "PASSED") {
			smart.Status = "PASSED"
		} else if strings.Contains(healthStr, "FAILED") {
			smart.Status = "FAILED"
			dh.Alerts = append(dh.Alerts, Alert{
				Level:   "red",
				Kind:    "smart_warning",
				Message: fmt.Sprintf("SMART health check FAILED for %s", devPath),
			})
		}
		dh.SMART = smart
	}

	// Get attributes for bad sectors and wear level.
	attrOut, _ := exec.Command(smartctlPath, "-A", devPath).Output()
	if len(attrOut) > 0 {
		parseSmartAttributes(dh, string(attrOut), opts)
	}

	return dh
}

// parseSmartAttributes extracts relevant SMART attributes from smartctl -A output.
func parseSmartAttributes(dh *DeviceHealth, output string, opts HealthOptions) {
	if dh.SMART == nil {
		dh.SMART = &SMART{Status: "UNKNOWN"}
	}

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		attrName := fields[1]
		rawValue := 0
		fmt.Sscanf(fields[9], "%d", &rawValue)

		switch attrName {
		case "Reallocated_Sector_Ct":
			dh.SMART.ReallocatedSectors = rawValue
			if rawValue > 0 {
				level := "yellow"
				if opts.BadSectorCritical > 0 && rawValue >= opts.BadSectorCritical {
					level = "red"
				}
				dh.Alerts = append(dh.Alerts, Alert{
					Level:   level,
					Kind:    "bad_sectors",
					Message: fmt.Sprintf("%d reallocated sectors on %s", rawValue, dh.Device),
				})
			}
		case "Current_Pending_Sector":
			dh.SMART.PendingSectors = rawValue
			if rawValue > 0 {
				dh.Alerts = append(dh.Alerts, Alert{
					Level:   "yellow",
					Kind:    "bad_sectors",
					Message: fmt.Sprintf("%d pending sectors on %s", rawValue, dh.Device),
				})
			}
		case "Wear_Leveling_Count", "SSD_Life_Left", "Media_Wearout_Indicator":
			dh.SMART.WearLevelPct = rawValue
			if opts.WearLevelCritical > 0 && rawValue <= opts.WearLevelCritical {
				dh.Alerts = append(dh.Alerts, Alert{
					Level:   "red",
					Kind:    "wear_level",
					Message: fmt.Sprintf("SSD wear level critical: %d%% remaining on %s", rawValue, dh.Device),
				})
			} else if opts.WearLevelWarn > 0 && rawValue <= opts.WearLevelWarn {
				dh.Alerts = append(dh.Alerts, Alert{
					Level:   "yellow",
					Kind:    "wear_level",
					Message: fmt.Sprintf("SSD wear level warning: %d%% remaining on %s", rawValue, dh.Device),
				})
			}
		}
	}
}

// supplementSmartctl enhances existing device entries with smartctl data if available.
func supplementSmartctl(devices []DeviceHealth, opts HealthOptions) []DeviceHealth {
	smartctlPath, err := exec.LookPath("smartctl")
	if err != nil {
		return devices
	}

	for i := range devices {
		dev := &devices[i]
		// Try to run smartctl -A on the device.
		attrOut, err := exec.Command(smartctlPath, "-A", dev.Device).Output()
		if err != nil {
			continue
		}
		parseSmartAttributes(dev, string(attrOut), opts)
	}

	return devices
}

// classifyMediaType converts Windows media type strings to our type system.
func classifyMediaType(mediaType string) string {
	lower := strings.ToLower(mediaType)
	switch {
	case strings.Contains(lower, "ssd") || strings.Contains(lower, "solid"):
		return "ssd"
	case strings.Contains(lower, "hdd") || strings.Contains(lower, "fixed hard"):
		return "hdd"
	case strings.Contains(lower, "removable"):
		return "usb"
	case strings.Contains(lower, "external"):
		return "usb"
	default:
		return "unknown"
	}
}

// DetectCapacityAnomaly checks for fake/counterfeit USB drives.
func DetectCapacityAnomaly(partitionSize, fsUsable int64, isRemovable bool) *Alert {
	if !isRemovable {
		return nil
	}
	ratio := float64(fsUsable) / float64(partitionSize)
	if ratio < 0.90 {
		return &Alert{
			Level:   "yellow",
			Kind:    "capacity_anomaly",
			Message: "Capacity anomaly: possible counterfeit storage device",
		}
	}
	return nil
}
