package cleaner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"distrike/hunter"
)

// CleanResult holds the result of a single cleanup execution.
type CleanResult struct {
	Prey       hunter.Prey `json:"prey"`
	FreedBytes int64       `json:"freed_bytes"`
	Success    bool        `json:"success"`
	Error      string      `json:"error,omitempty"`
}

// HistoryEntry records a cleanup action for auditing.
type HistoryEntry struct {
	Timestamp  string      `json:"timestamp"`
	Prey       hunter.Prey `json:"prey"`
	FreedBytes int64       `json:"freed_bytes"`
	Success    bool        `json:"success"`
	Error      string      `json:"error,omitempty"`
}

// Execute runs the cleanup action for a prey item.
// Returns the number of bytes freed.
func Execute(prey hunter.Prey) (int64, error) {
	if prey.Action.Type == "manual" {
		return 0, fmt.Errorf("manual action: %s", prey.Action.Hint)
	}

	if prey.Action.Command == "" {
		return 0, fmt.Errorf("no cleanup command for %s", prey.Path)
	}

	// Measure space before
	var beforeFree int64
	if info, err := os.Stat(prey.Path); err == nil {
		if info.IsDir() {
			beforeFree = dirSize(prey.Path)
		} else {
			beforeFree = info.Size()
		}
	}

	// Execute the command
	cmd := buildCommand(prey.Action.Command, prey.Action.Shell)
	cmd.Stdout = os.Stderr // progress to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("executing cleanup for %s: %w", prey.Path, err)
	}

	// Measure space after
	var afterFree int64
	if info, err := os.Stat(prey.Path); err == nil {
		if info.IsDir() {
			afterFree = dirSize(prey.Path)
		} else {
			afterFree = info.Size()
		}
	}
	// If the path no longer exists, all space was freed
	freed := beforeFree - afterFree
	if freed < 0 {
		freed = 0
	}
	return freed, nil
}

// selfProtectPaths returns paths that must not be deleted during cleanup.
// Includes the current process's temp directory and executable path.
func selfProtectPaths() map[string]bool {
	protected := make(map[string]bool)

	// Protect the directory containing the current executable
	if exe, err := os.Executable(); err == nil {
		protected[filepath.Dir(exe)] = true
	}

	// Protect TEMP subdirectories belonging to the current process's parent tools.
	// Claude Code (and similar) store output in TEMP/claude/<project>/<session>/tasks/
	// Pattern: any directory under TEMP that contains our PID or "claude" or "distrike"
	tmpDir := os.TempDir()
	if entries, err := os.ReadDir(tmpDir); err == nil {
		pid := fmt.Sprintf("%d", os.Getpid())
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			// Protect claude/distrike working directories and PID-named dirs
			if name == "claude" || name == "distrike" || name == pid {
				protected[filepath.Join(tmpDir, name)] = true
			}
		}
	}

	return protected
}

// isProtected checks if a path is or is under a protected path.
func isProtected(path string, protected map[string]bool) bool {
	clean := filepath.Clean(path)
	for p := range protected {
		if clean == p || strings.HasPrefix(clean, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// CleanContents deletes all files and subdirectories inside a directory,
// but preserves the directory itself. Used for SAFE manual prey like
// Temp, CrashDumps, browser caches, etc.
// Automatically skips the current process's temp files to avoid
// deleting its own output mid-execution.
// Returns the number of bytes freed.
func CleanContents(dirPath string) (int64, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", dirPath, err)
	}
	if !info.IsDir() {
		// Single file: just delete it
		size := info.Size()
		if err := os.Remove(dirPath); err != nil {
			return 0, fmt.Errorf("removing %s: %w", dirPath, err)
		}
		return size, nil
	}

	protected := selfProtectPaths()
	before := dirSize(dirPath)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", dirPath, err)
	}

	var lastErr error
	var skipped int
	for _, entry := range entries {
		p := filepath.Join(dirPath, entry.Name())
		if isProtected(p, protected) {
			skipped++
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			lastErr = err // continue cleaning others
		}
	}

	after := dirSize(dirPath)
	freed := before - after
	if freed < 0 {
		freed = 0
	}

	if lastErr != nil {
		msg := fmt.Sprintf("partial cleanup (%s freed)", formatBytes(freed))
		if skipped > 0 {
			msg += fmt.Sprintf(", %d items skipped (in use by current process)", skipped)
		}
		return freed, fmt.Errorf("%s, last error: %w", msg, lastErr)
	}
	return freed, nil
}

// formatBytes is a minimal size formatter for error messages.
func formatBytes(b int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// buildCommand creates an exec.Cmd for the given command string and shell preference.
func buildCommand(command, shell string) *exec.Cmd {
	if shell == "" {
		shell = "default"
	}

	switch shell {
	case "powershell":
		return exec.Command("powershell", "-NoProfile", "-Command", command)
	case "bash":
		return exec.Command("bash", "-c", command)
	default:
		if runtime.GOOS == "windows" {
			return exec.Command("cmd", "/C", command)
		}
		return exec.Command("sh", "-c", command)
	}
}

// dirSize computes the total size of a directory tree.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// historyPath returns the path to the cleanup history file.
func historyPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "distrike", "clean_history.json")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "distrike", "clean_history.json")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "distrike", "clean_history.json")
	}
}

// RecordHistory appends a cleanup record to the history file.
func RecordHistory(prey hunter.Prey, freedBytes int64, success bool, errMsg string) error {
	entry := HistoryEntry{
		Timestamp:  time.Now().Format(time.RFC3339),
		Prey:       prey,
		FreedBytes: freedBytes,
		Success:    success,
		Error:      errMsg,
	}

	history, _ := LoadHistory()
	history = append(history, entry)

	// Ensure directory exists
	dir := filepath.Dir(historyPath())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating history directory: %w", err)
	}

	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling history: %w", err)
	}
	return os.WriteFile(historyPath(), data, 0644)
}

// LoadHistory reads the cleanup history from disk.
func LoadHistory() ([]HistoryEntry, error) {
	data, err := os.ReadFile(historyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading history: %w", err)
	}
	var history []HistoryEntry
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("parsing history: %w", err)
	}
	return history, nil
}
