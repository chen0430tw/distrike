package cleaner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
