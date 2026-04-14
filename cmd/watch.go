package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"distrike/config"
	"distrike/internal/units"
	"distrike/killline"
	dSignal "distrike/signal"

	"github.com/spf13/cobra"
)

var (
	watchInterval string
	watchDaemon   bool
	watchAll      bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor capacity rebound and alert when free space approaches kill-line",
	Long:  `Continuously poll drive free space at a given interval and emit alerts when free space drops near or below the kill-line threshold.`,
	RunE:  runWatch,
}

func init() {
	watchCmd.Flags().StringVar(&watchInterval, "interval", "5s", "polling interval (e.g. 5s, 1m, 30s)")
	watchCmd.Flags().BoolVar(&watchDaemon, "daemon", false, "daemon mode: GC every 100 iterations, hourly memory stats")
	watchCmd.Flags().BoolVar(&watchAll, "all", false, "watch all drives (default: only drives with signals)")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	killLineBytes, err := units.ParseSize(cfg.KillLine)
	if err != nil {
		return fmt.Errorf("parsing kill_line %q: %w", cfg.KillLine, err)
	}

	// Adaptive polling intervals — tighter signal = more frequent checks.
	// Configurable via config watch.intervals, with sensible defaults.
	type adaptiveIntervals struct {
		purple time.Duration // < 1GB: imminent danger
		red    time.Duration // < kill_line: dangerous
		yellow time.Duration // < kill_line * 1.5: approaching
		green  time.Duration // safe: just heartbeat
	}

	intervals := adaptiveIntervals{
		purple: 10 * time.Second,
		red:    30 * time.Second,
		yellow: 5 * time.Minute,
		green:  15 * time.Minute,
	}

	// Override from config if available
	if cfg.Watch.PurpleInterval != "" {
		if d, err := units.ParseDuration(cfg.Watch.PurpleInterval); err == nil {
			intervals.purple = d
		}
	}
	if cfg.Watch.RedInterval != "" {
		if d, err := units.ParseDuration(cfg.Watch.RedInterval); err == nil {
			intervals.red = d
		}
	}
	if cfg.Watch.YellowInterval != "" {
		if d, err := units.ParseDuration(cfg.Watch.YellowInterval); err == nil {
			intervals.yellow = d
		}
	}
	if cfg.Watch.GreenInterval != "" {
		if d, err := units.ParseDuration(cfg.Watch.GreenInterval); err == nil {
			intervals.green = d
		}
	}

	// CLI --interval overrides the worst-case (purple) interval
	if watchInterval != "5s" {
		if d, err := units.ParseDuration(watchInterval); err == nil {
			intervals.purple = d
		}
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	thresholds := dSignal.DefaultThresholds()

	fmt.Fprintf(cmd.ErrOrStderr(), "Watching drives (kill-line: %s)\n", units.FormatSize(killLineBytes))
	fmt.Fprintf(cmd.ErrOrStderr(), "  Adaptive intervals: PURPLE=%s RED=%s YELLOW=%s GREEN=%s\n",
		intervals.purple, intervals.red, intervals.yellow, intervals.green)

	iteration := 0
	lastMemReport := time.Now()
	currentInterval := 1 * time.Millisecond // first check immediately

	for {
		timer := time.NewTimer(currentInterval)
		select {
		case <-sigCh:
			timer.Stop()
			fmt.Fprintf(cmd.ErrOrStderr(), "\n[%s] Watch stopped by signal\n", time.Now().Format("15:04:05"))
			return nil
		case <-timer.C:
			iteration++

			drives, err := killline.EnumerateDrives()
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[%s] Error enumerating drives: %v\n", time.Now().Format("15:04:05"), err)
				continue
			}

			// Determine the worst signal across all drives to set next interval
			worstLevel := 0 // 0=green, 1=yellow, 2=red, 3=purple

			for _, d := range drives {
				var usedRatio float64
				if d.TotalBytes > 0 {
					usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
				}

				sig := dSignal.Classify(usedRatio, 0, d.FreeBytes, killLineBytes, thresholds)

				ts := time.Now().Format("15:04:05")
				yellowLine := int64(float64(killLineBytes) * 1.5)

				if d.FreeBytes < 1<<30 { // < 1GB
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] PURPLE %s: %s free (< 1 GB!) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
					if worstLevel < 3 {
						worstLevel = 3
					}
				} else if d.FreeBytes < killLineBytes {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] RED %s: %s free (below kill-line %s) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), units.FormatSize(killLineBytes), sig.Light)
					if worstLevel < 2 {
						worstLevel = 2
					}
				} else if d.FreeBytes < yellowLine {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] YELLOW %s: %s free (approaching kill-line) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
					if worstLevel < 1 {
						worstLevel = 1
					}
				} else if watchAll {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] GREEN %s: %s free signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
				}
			}

			// Adapt interval based on worst signal
			switch worstLevel {
			case 3:
				currentInterval = intervals.purple
			case 2:
				currentInterval = intervals.red
			case 1:
				currentInterval = intervals.yellow
			default:
				currentInterval = intervals.green
			}

			// Daemon mode: GC and memory stats
			if watchDaemon {
				if iteration%100 == 0 {
					runtime.GC()
				}
				if time.Since(lastMemReport) >= time.Hour {
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] Memory: Alloc=%s Sys=%s NumGC=%d\n",
						time.Now().Format("15:04:05"),
						units.FormatSize(int64(m.Alloc)),
						units.FormatSize(int64(m.Sys)),
						m.NumGC)
					lastMemReport = time.Now()
				}
			}
		}
	}
}
