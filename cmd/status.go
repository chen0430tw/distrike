package cmd

import (
	"fmt"
	"os"

	"distrike/config"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/output"
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

	hasWarning := false

	for _, d := range drives {
		var usedRatio float64
		if d.TotalBytes > 0 {
			usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
		}

		// Compute concentration as 0 for status (no scan data)
		sig := signal.Classify(usedRatio, 0, d.FreeBytes, killLineBytes, thresholds)

		if sig.Light == signal.Red || sig.Light == signal.Purple {
			hasWarning = true
		}

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

	if hasWarning {
		os.Exit(1)
	}
	return nil
}
