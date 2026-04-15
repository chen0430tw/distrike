package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"distrike/config"
	"distrike/health"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/output"
	"distrike/security"
	"distrike/signal"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show kill-line status and capacity signals for all drives",
	Long:  `Display a quick overview of all drives/mount points with capacity signal lights (GREEN/YELLOW/RED/PURPLE), free space, and kill-line proximity.`,
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	killLineBytes, err := units.ParseSize(cfg.KillLine)
	if err != nil {
		return fmt.Errorf("parsing kill_line %q: %w", cfg.KillLine, err)
	}

	drives, err := killline.EnumerateDrives()
	if err != nil {
		return fmt.Errorf("enumerating drives: %w", err)
	}

	thresholds := signal.DefaultThresholds()

	statusData := output.StatusOutput{
		KillLineBytes: killLineBytes,
	}

	for _, d := range drives {
		var usedRatio float64
		if d.TotalBytes > 0 {
			usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
		}

		// Compute concentration as 0 for status (no scan data)
		sig := signal.Classify(usedRatio, 0, d.FreeBytes, killLineBytes, thresholds)

		statusData.Drives = append(statusData.Drives, output.DriveOutput{
			Path:       d.Path,
			TotalBytes: d.TotalBytes,
			FreeBytes:  d.FreeBytes,
			UsedBytes:  d.UsedBytes,
			Signal:     sig,
			Removable:  d.Removable,
		})
	}

	// Collect virtual disk info
	statusData.VDisks = collectVDisks()

	result := output.RenderStatus(statusData, jsonOutput)
	fmt.Println(result)

	// Health checks
	if cfg.Health.Enabled {
		opts := health.HealthOptions{
			SMARTEnabled:      cfg.Health.SMART.Enabled,
			CapacityAnomaly:   cfg.Health.CapacityAnomaly.Enabled,
			RemovableOnly:     cfg.Health.CapacityAnomaly.RemovableOnly,
			BadSectorWarn:     cfg.Health.BadSectors.WarnThreshold,
			BadSectorCritical: cfg.Health.BadSectors.CritThreshold,
			WearLevelWarn:     cfg.Health.WearLevel.WarnPct,
			WearLevelCritical: cfg.Health.WearLevel.CritPct,
		}
		devices, err := health.Check(opts)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Health check error: %v\n", err)
		} else {
			for _, dev := range devices {
				for _, alert := range dev.Alerts {
					fmt.Fprintf(cmd.ErrOrStderr(), "[HEALTH %s] %s: %s\n", alert.Level, dev.Device, alert.Message)
				}
			}
		}
	}

	// Encryption detection
	if cfg.Security.Encryption.Detect {
		states, err := security.DetectEncryption()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Encryption detection error: %v\n", err)
		} else {
			for _, es := range states {
				if es.Method != "none" && es.Method != "unknown" {
					fmt.Fprintf(cmd.ErrOrStderr(), "[ENCRYPTION] %s: %s (%s)\n", es.Drive, es.Method, es.State)
				}
			}
		}
	}

	// Note: previously exited 1 on RED/PURPLE, but this causes confusing
	// "Error: Exit code 1" in interactive terminals. The colored output
	// already communicates danger clearly. Scripts can parse --json output.
	return nil
}

// collectVDisks finds known virtual disk files (WSL, Docker, Claude VM, LDPlayer, etc.)
func collectVDisks() []output.VDiskEntry {
	if runtime.GOOS != "windows" {
		return nil
	}

	var results []output.VDiskEntry
	home := os.Getenv("USERPROFILE")

	// Known VHDX/VMDK locations to probe
	type probe struct {
		name    string
		pattern string // glob pattern
	}

	probes := []probe{
		{"WSL", filepath.Join(home, "AppData", "Local", "Packages", "*", "LocalState", "ext4.vhdx")},
		{"Docker", filepath.Join(home, "AppData", "Local", "Docker", "wsl", "**", "ext4.vhdx")},
		{"Claude VM", filepath.Join(home, "AppData", "Roaming", "Claude", "vm_bundles", "*", "*.vhdx")},
	}

	// Check all mounted drives for Docker/LDPlayer vdisks
	driveList, _ := killline.EnumerateDrives()
	for _, drv := range driveList {
		d := strings.TrimRight(drv.Path, `\`)
		probes = append(probes, probe{"Docker", d + `\Docker\DockerDesktopWSL\*\*.vhdx`})
		probes = append(probes, probe{"LDPlayer", d + `\LDPlayer\LDPlayer*\vms\*\*.vmdk`})
		probes = append(probes, probe{"LDPlayer", d + `\LDPlayer\LDPlayer*\*.vmdk`})
	}

	seen := make(map[string]bool)
	for _, p := range probes {
		matches, _ := filepath.Glob(p.pattern)
		for _, m := range matches {
			abs, _ := filepath.Abs(m)
			if seen[strings.ToLower(abs)] {
				continue
			}
			seen[strings.ToLower(abs)] = true

			info, err := os.Stat(abs)
			if err != nil {
				continue
			}

			name := p.name
			// Enrich WSL name with distro info from path
			if name == "WSL" {
				parts := strings.Split(abs, string(filepath.Separator))
				for _, part := range parts {
					if strings.Contains(part, "Ubuntu") || strings.Contains(part, "Debian") ||
						strings.Contains(part, "openSUSE") || strings.Contains(part, "kali") ||
						strings.Contains(part, "Fedora") || strings.Contains(part, "Arch") {
						// Extract distro name from package path
						idx := strings.LastIndex(part, "_")
						if idx > 0 {
							name = "WSL " + part[:idx]
							// Simplify common names
							name = strings.Replace(name, "CanonicalGroupLimited.", "", 1)
						}
						break
					}
				}
			}

			results = append(results, output.VDiskEntry{
				Name:      name,
				Path:      abs,
				SizeBytes: info.Size(),
			})
		}
	}

	return results
}
