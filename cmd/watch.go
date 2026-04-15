package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"distrike/config"
	"distrike/internal/notify"
	"distrike/internal/units"
	"distrike/killline"
	dSignal "distrike/signal"

	"github.com/spf13/cobra"
)

var (
	watchInterval  string
	watchDaemon    bool
	watchAll       bool
	watchInstall   bool
	watchUninstall bool
	watchStatus    bool
	watchAutoClean bool
	watchNoNotify  bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor capacity rebound and alert when free space approaches kill-line",
	Long: `Continuously poll drive free space at a given interval and emit alerts
when free space drops near or below the kill-line threshold.

Adaptive intervals: polls faster when drives are in danger, relaxes when safe.

Use --install to register as a Windows scheduled task (runs at login).
Use --uninstall to remove the scheduled task.
Use --status to check if the background task is running.`,
	RunE: runWatch,
}

const taskName = "DistrikeWatch"

func init() {
	watchCmd.Flags().StringVar(&watchInterval, "interval", "5s", "override purple interval (e.g. 5s, 1m)")
	watchCmd.Flags().BoolVar(&watchDaemon, "daemon", false, "daemon mode: GC + memory management")
	watchCmd.Flags().BoolVar(&watchAll, "all", false, "watch all drives (default: only alerting drives)")
	watchCmd.Flags().BoolVar(&watchAutoClean, "auto-clean", false, "auto-run 'clean --risk safe' when signal hits RED/PURPLE")
	watchCmd.Flags().BoolVar(&watchNoNotify, "no-notify", false, "disable desktop notifications")
	watchCmd.Flags().BoolVar(&watchInstall, "install", false, "register as Windows scheduled task (runs at login)")
	watchCmd.Flags().BoolVar(&watchUninstall, "uninstall", false, "remove the scheduled task")
	watchCmd.Flags().BoolVar(&watchStatus, "status", false, "check if watch is running")
	rootCmd.AddCommand(watchCmd)
}

func runWatch(cmd *cobra.Command, args []string) error {
	// Handle --install / --uninstall / --status before anything else
	if watchInstall {
		return installWatchTask(cmd)
	}
	if watchUninstall {
		return uninstallWatchTask(cmd)
	}
	if watchStatus {
		return showWatchStatus(cmd)
	}

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
	if watchAutoClean {
		fmt.Fprintf(cmd.ErrOrStderr(), "  Auto-clean: enabled (will run 'clean --risk safe' on RED/PURPLE)\n")
	}
	if watchNoNotify {
		fmt.Fprintf(cmd.ErrOrStderr(), "  Notifications: disabled\n")
	}

	iteration := 0
	lastMemReport := time.Now()
	currentInterval := 1 * time.Millisecond // first check immediately
	prevWorstLevel := 0                      // track signal changes for notification
	lastAutoClean := time.Time{}             // cooldown for auto-clean
	const autoCleanCooldown = 10 * time.Minute

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
			var worstDrive string
			var worstFree int64

			for _, d := range drives {
				var usedRatio float64
				if d.TotalBytes > 0 {
					usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
				}

				sig := dSignal.Classify(usedRatio, 0, d.FreeBytes, killLineBytes, thresholds)

				ts := time.Now().Format("15:04:05")
				yellowLine := int64(float64(killLineBytes) * 1.5)

				level := 0
				if d.FreeBytes < 1<<30 { // < 1GB
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] PURPLE %s: %s free (< 1 GB!) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
					level = 3
				} else if d.FreeBytes < killLineBytes {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] RED %s: %s free (below kill-line %s) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), units.FormatSize(killLineBytes), sig.Light)
					level = 2
				} else if d.FreeBytes < yellowLine {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] YELLOW %s: %s free (approaching kill-line) signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
					level = 1
				} else if watchAll {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] GREEN %s: %s free signal=%s\n",
						ts, d.Path, units.FormatSize(d.FreeBytes), sig.Light)
				}

				if level > worstLevel {
					worstLevel = level
					worstDrive = d.Path
					worstFree = d.FreeBytes
				}
			}

			// Desktop notification when signal worsens
			if !watchNoNotify && worstLevel > prevWorstLevel && worstLevel >= 2 {
				levelNames := []string{"GREEN", "YELLOW", "RED", "PURPLE"}
				title := fmt.Sprintf("Distrike: %s", levelNames[worstLevel])
				msg := fmt.Sprintf("%s only %s free", worstDrive, units.FormatSize(worstFree))
				if worstLevel == 3 {
					msg += " — CRITICAL, immediate cleanup needed!"
				} else {
					msg += " — below kill-line, cleanup recommended"
				}
				_ = notify.Send(title, msg)
			}
			prevWorstLevel = worstLevel

			// Auto-clean on RED/PURPLE (with cooldown to avoid spamming)
			if watchAutoClean && worstLevel >= 2 && time.Since(lastAutoClean) > autoCleanCooldown {
				ts := time.Now().Format("15:04:05")
				fmt.Fprintf(cmd.ErrOrStderr(), "[%s] Auto-clean triggered (signal=%s)\n",
					ts, []string{"GREEN", "YELLOW", "RED", "PURPLE"}[worstLevel])
				exePath, _ := os.Executable()
				cleanCmd := exec.Command(exePath, "clean", "--risk", "safe", "--yes")
				cleanCmd.Stdout = cmd.ErrOrStderr()
				cleanCmd.Stderr = cmd.ErrOrStderr()
				if err := cleanCmd.Run(); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "[%s] Auto-clean error: %v\n", ts, err)
				}
				lastAutoClean = time.Now()
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

// installWatchTask registers distrike watch as a background service.
// Windows: schtasks (scheduled task at logon)
// macOS: launchd plist
// Linux: systemd user service
func installWatchTask(cmd *cobra.Command) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding executable path: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	switch runtime.GOOS {
	case "windows":
		// schtasks /Create /TN DistrikeWatch /TR "path\distrike.exe watch --daemon --all" /SC ONLOGON /RL HIGHEST
		taskCmd := fmt.Sprintf(`"%s" watch --daemon --all`, exePath)
		out, err := exec.Command("schtasks", "/Create",
			"/TN", taskName,
			"/TR", taskCmd,
			"/SC", "ONLOGON",
			"/RL", "HIGHEST",
			"/F", // force overwrite if exists
		).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks create: %s\n%w", string(out), err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Installed scheduled task '%s'\n", taskName)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Command: %s\n", taskCmd)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Trigger: at logon\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "  To start now: schtasks /Run /TN %s\n", taskName)

	case "darwin":
		plistName := "com.distrike.watch"
		plistPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", plistName+".plist")
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>watch</string>
        <string>--daemon</string>
        <string>--all</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/distrike-watch.log</string>
</dict>
</plist>`, plistName, exePath)
		if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
			return fmt.Errorf("writing plist: %w", err)
		}
		exec.Command("launchctl", "load", plistPath).Run()
		fmt.Fprintf(cmd.ErrOrStderr(), "Installed launchd agent '%s'\n", plistName)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Plist: %s\n", plistPath)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Log: /tmp/distrike-watch.log\n")

	default: // Linux
		serviceDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
		os.MkdirAll(serviceDir, 0755)
		servicePath := filepath.Join(serviceDir, "distrike-watch.service")
		service := fmt.Sprintf(`[Unit]
Description=Distrike capacity rebound monitor

[Service]
ExecStart=%s watch --daemon --all
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
`, exePath)
		if err := os.WriteFile(servicePath, []byte(service), 0644); err != nil {
			return fmt.Errorf("writing service file: %w", err)
		}
		exec.Command("systemctl", "--user", "daemon-reload").Run()
		exec.Command("systemctl", "--user", "enable", "distrike-watch").Run()
		exec.Command("systemctl", "--user", "start", "distrike-watch").Run()
		fmt.Fprintf(cmd.ErrOrStderr(), "Installed systemd user service 'distrike-watch'\n")
		fmt.Fprintf(cmd.ErrOrStderr(), "  Service: %s\n", servicePath)
		fmt.Fprintf(cmd.ErrOrStderr(), "  Status: systemctl --user status distrike-watch\n")
	}
	return nil
}

// uninstallWatchTask removes the background service.
func uninstallWatchTask(cmd *cobra.Command) error {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks delete: %s\n%w", string(out), err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Removed scheduled task '%s'\n", taskName)

	case "darwin":
		plistName := "com.distrike.watch"
		plistPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", plistName+".plist")
		exec.Command("launchctl", "unload", plistPath).Run()
		os.Remove(plistPath)
		fmt.Fprintf(cmd.ErrOrStderr(), "Removed launchd agent '%s'\n", plistName)

	default:
		exec.Command("systemctl", "--user", "stop", "distrike-watch").Run()
		exec.Command("systemctl", "--user", "disable", "distrike-watch").Run()
		servicePath := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "distrike-watch.service")
		os.Remove(servicePath)
		exec.Command("systemctl", "--user", "daemon-reload").Run()
		fmt.Fprintf(cmd.ErrOrStderr(), "Removed systemd user service 'distrike-watch'\n")
	}
	return nil
}

// showWatchStatus checks if the background watch task is running.
func showWatchStatus(cmd *cobra.Command) error {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("schtasks", "/Query", "/TN", taskName, "/FO", "LIST").CombinedOutput()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch task not installed\n")
			return nil
		}
		// Check if running
		if strings.Contains(string(out), "Running") {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: RUNNING\n")
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: INSTALLED (not currently running)\n")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s", string(out))

	case "darwin":
		out, _ := exec.Command("launchctl", "list", "com.distrike.watch").CombinedOutput()
		if strings.Contains(string(out), "distrike") {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: RUNNING\n")
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: NOT RUNNING\n")
		}

	default:
		out, _ := exec.Command("systemctl", "--user", "is-active", "distrike-watch").CombinedOutput()
		status := strings.TrimSpace(string(out))
		if status == "active" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: RUNNING\n")
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Watch: %s\n", strings.ToUpper(status))
		}
		detail, _ := exec.Command("systemctl", "--user", "status", "distrike-watch").CombinedOutput()
		fmt.Fprintf(cmd.OutOrStdout(), "%s", string(detail))
	}
	return nil
}
