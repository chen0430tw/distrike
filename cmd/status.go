package cmd

import (
	"fmt"

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
		})
	}

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
