package units

import (
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ParseSize parses human-readable size strings like "20GB", "100MB", "1TB".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	// Check longer suffixes first to avoid "GB" matching "B" suffix.
	type suffixMult struct {
		suffix string
		mult   int64
	}
	suffixes := []suffixMult{
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"B", 1},
	}
	for _, sm := range suffixes {
		if strings.HasSuffix(s, sm.suffix) {
			numStr := strings.TrimSuffix(s, sm.suffix)
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q: %w", s, err)
			}
			return int64(num * float64(sm.mult)), nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	return n, nil
}

// FormatSize formats bytes as human-readable string.
func FormatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	size := float64(bytes)
	for _, unit := range units {
		size /= 1024
		if size < 1024 || unit == "TB" {
			if size == math.Trunc(size) {
				return fmt.Sprintf("%.0f %s", size, unit)
			}
			return fmt.Sprintf("%.1f %s", size, unit)
		}
	}
	return fmt.Sprintf("%.1f TB", size)
}

// NormalizePath fixes common path issues on Windows:
//   - Bare drive letter "D:" → "D:\"
//   - Forward slashes "D:/" → "D:\"
//   - Trailing slash consistency
//
// On non-Windows, returns filepath.Clean(path).
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if runtime.GOOS == "windows" {
		// Convert forward slashes to backslashes
		path = filepath.FromSlash(path)
		// Bare drive letter: "D:" → "D:\"
		if len(path) == 2 && path[1] == ':' {
			path += `\`
		}
		// Drive with forward slash already converted: ensure root
		if len(path) == 3 && path[1] == ':' && path[2] == '\\' {
			return path
		}
	}
	return filepath.Clean(path)
}

// ParseDuration parses duration strings like "30m", "1h", "6h", "24h", "7d".
// Supports Go standard durations plus "d" suffix for days.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Handle day suffix (not supported by time.ParseDuration)
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		num, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(num * float64(24*time.Hour)), nil
	}

	// Try standard Go duration parsing (handles "30m", "1h", "6h", "24h", etc.)
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d, nil
}
