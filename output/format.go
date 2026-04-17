package output

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// Format is the requested output format for a Render* call.
type Format int

const (
	// FormatAuto: FormatTable if stdout is a TTY, else FormatTSV.
	FormatAuto Format = iota
	FormatTable
	FormatTSV
	FormatJSON
)

// ParseFormat maps a user-supplied string to a Format. Empty/invalid ⇒ FormatAuto.
// Accepted: "auto", "table", "tsv", "json".
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return FormatAuto
	case "table":
		return FormatTable
	case "tsv":
		return FormatTSV
	case "json":
		return FormatJSON
	default:
		return FormatAuto
	}
}

// ResolveAuto returns an explicit Format. If f is FormatAuto, it picks
// FormatTable when stdout is a TTY and FormatTSV otherwise. Other values
// pass through unchanged.
func ResolveAuto(f Format) Format {
	if f != FormatAuto {
		return f
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		return FormatTable
	}
	return FormatTSV
}

// FormatFromFlags combines the legacy --json bool flag with the new --format
// string flag. --format takes precedence when set to anything non-empty.
func FormatFromFlags(jsonFlag bool, formatFlag string) Format {
	if formatFlag != "" {
		return ParseFormat(formatFlag)
	}
	if jsonFlag {
		return FormatJSON
	}
	return FormatAuto
}
