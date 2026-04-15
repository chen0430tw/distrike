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
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	size := float64(bytes)
	for _, unit := range units {
		size /= 1024
		if size < 1024 || unit == "PB" {
			if size == math.Trunc(size) {
				return fmt.Sprintf("%.0f %s", size, unit)
			}
			return fmt.Sprintf("%.1f %s", size, unit)
		}
	}
	return fmt.Sprintf("%.1f PB", size)
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

// ParseDateShortcut parses time filter shortcuts (ported from doc_searcher.py).
//
// Supported formats:
//
//	td / today       → today 00:00
//	yd / yesterday   → yesterday 00:00
//	tw / thisweek    → Monday of this week 00:00
//	lw / lastweek    → Monday of last week 00:00
//	tm / thismonth   → 1st of this month 00:00
//	lm / lastmonth   → 1st of last month 00:00
//	ty / thisyear    → Jan 1 of this year 00:00
//	ly / lastyear    → Jan 1 of last year 00:00
//	Nd               → N days ago (e.g., 3d, 7d, 30d)
//	Nh               → N hours ago (e.g., 1h, 6h, 24h)
//	Nw               → N weeks ago (e.g., 1w, 2w)
//	@1700000000      → Unix timestamp
//	YYYY-MM-DD       → Exact date
func ParseDateShortcut(s string) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	shortcuts := map[string]time.Time{
		"td":        todayStart,
		"today":     todayStart,
		"yd":        todayStart.AddDate(0, 0, -1),
		"yesterday": todayStart.AddDate(0, 0, -1),
		"tw":        todayStart.AddDate(0, 0, -int(todayStart.Weekday()-time.Monday+7)%7),
		"thisweek":  todayStart.AddDate(0, 0, -int(todayStart.Weekday()-time.Monday+7)%7),
		"lw":        todayStart.AddDate(0, 0, -int(todayStart.Weekday()-time.Monday+7)%7-7),
		"lastweek":  todayStart.AddDate(0, 0, -int(todayStart.Weekday()-time.Monday+7)%7-7),
		"tm":        time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()),
		"thismonth": time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()),
		"ty":        time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location()),
		"thisyear":  time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location()),
		"ly":        time.Date(now.Year()-1, 1, 1, 0, 0, 0, 0, now.Location()),
		"lastyear":  time.Date(now.Year()-1, 1, 1, 0, 0, 0, 0, now.Location()),
	}

	if t, ok := shortcuts[s]; ok {
		return t, nil
	}

	// lm / lastmonth (needs special handling for January)
	if s == "lm" || s == "lastmonth" {
		m := now.Month() - 1
		y := now.Year()
		if m < 1 {
			m = 12
			y--
		}
		return time.Date(y, m, 1, 0, 0, 0, 0, now.Location()), nil
	}

	// Relative offset: Nd, Nh, Nw
	if len(s) >= 2 {
		suffix := s[len(s)-1]
		numStr := s[:len(s)-1]
		if n, err := strconv.Atoi(numStr); err == nil {
			switch suffix {
			case 'd':
				return now.Add(-time.Duration(n) * 24 * time.Hour), nil
			case 'h':
				return now.Add(-time.Duration(n) * time.Hour), nil
			case 'w':
				return now.Add(-time.Duration(n) * 7 * 24 * time.Hour), nil
			}
		}
	}

	// Unix timestamp: @1700000000
	if strings.HasPrefix(s, "@") {
		ts, err := strconv.ParseInt(s[1:], 10, 64)
		if err == nil {
			return time.Unix(ts, 0), nil
		}
	}

	// Standard date formats
	for _, layout := range []string{"2006-01-02", "2006-01-02 15:04:05", "2006/01/02", "20060102"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("cannot parse date: %q (use td/yd/3d/7d/tw/lw/tm/lm/ty/ly/@timestamp/YYYY-MM-DD)", s)
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
