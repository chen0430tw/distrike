package output

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"distrike/hunter"
	"distrike/internal/units"
	"distrike/signal"
)

const (
	toolName    = "distrike"
	toolVersion = "0.1.0"
	schemaVer   = "1.0"
)

// StatusOutput is the JSON schema for distrike status.
type StatusOutput struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          string        `json:"tool"`
	ToolVersion   string        `json:"tool_version"`
	Timestamp     string        `json:"timestamp"`
	Platform      string        `json:"platform"`
	KillLineBytes int64         `json:"kill_line_bytes"`
	Drives        []DriveOutput `json:"drives"`
}

// DriveOutput is the per-drive section of status output.
type DriveOutput struct {
	Path       string        `json:"path"`
	TotalBytes int64         `json:"total_bytes"`
	FreeBytes  int64         `json:"free_bytes"`
	UsedBytes  int64         `json:"used_bytes"`
	Signal     signal.Signal `json:"signal"`
}

// ScanOutput is the JSON schema for distrike scan.
type ScanOutput struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          string      `json:"tool"`
	ToolVersion   string      `json:"tool_version"`
	Timestamp     string      `json:"timestamp"`
	Platform      string      `json:"platform"`
	Data          ScanData    `json:"data"`
}

// ScanData holds scan result data.
type ScanData struct {
	RootPath     string      `json:"root_path"`
	TotalBytes   int64       `json:"total_bytes"`
	FreeBytes    int64       `json:"free_bytes"`
	UsedBytes    int64       `json:"used_bytes"`
	Entries      []ScanEntry `json:"entries"`
	ScanCoverage float64     `json:"scan_coverage"`
	DurationMs   int64       `json:"scan_duration_ms"`
	EngineName   string      `json:"scan_engine"`
}

// ScanEntry is an entry in scan output.
type ScanEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SizeHuman string `json:"size_human"`
	IsDir     bool   `json:"is_dir"`
	Children  int    `json:"children_count,omitempty"`
}

// HuntOutput is the JSON schema for distrike hunt.
type HuntOutput struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          string       `json:"tool"`
	ToolVersion   string       `json:"tool_version"`
	Timestamp     string       `json:"timestamp"`
	Platform      string       `json:"platform"`
	Data          HuntData     `json:"data"`
}

// HuntData holds hunt result data.
type HuntData struct {
	Prey    []hunter.Prey `json:"prey"`
	Summary HuntSummary   `json:"summary"`
}

// HuntSummary summarizes hunt results.
type HuntSummary struct {
	TotalPrey      int    `json:"total_prey"`
	TotalBytes     int64  `json:"total_bytes"`
	TotalHuman     string `json:"total_human"`
	SafeCount      int    `json:"safe_count"`
	SafeBytes      int64  `json:"safe_bytes"`
	CautionCount   int    `json:"caution_count"`
	CautionBytes   int64  `json:"caution_bytes"`
	DangerCount    int    `json:"danger_count"`
	DangerBytes    int64  `json:"danger_bytes"`
}

// CleanOutput is the JSON schema for distrike clean.
type CleanOutput struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	Timestamp     string    `json:"timestamp"`
	Platform      string    `json:"platform"`
	Data          CleanData `json:"data"`
}

// CleanData holds clean result data.
type CleanData struct {
	Cleaned    []CleanedItem `json:"cleaned"`
	FreedBytes int64         `json:"freed_bytes"`
	FreedHuman string        `json:"freed_human"`
	Errors     []string      `json:"errors,omitempty"`
}

// CleanedItem represents a single cleaned prey.
type CleanedItem struct {
	Path       string `json:"path"`
	SizeBytes  int64  `json:"size_bytes"`
	SizeHuman  string `json:"size_human"`
	Kind       string `json:"kind"`
	Risk       string `json:"risk"`
	Command    string `json:"command,omitempty"`
	FreedBytes int64  `json:"freed_bytes"`
}

func now() string {
	return time.Now().Format(time.RFC3339)
}

func platform() string {
	return runtime.GOOS
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorPurple = "\033[35m"
)

// signalLabel returns a colored text label for a signal light.
func signalLabel(l signal.Light) string {
	switch l {
	case signal.Purple:
		return colorPurple + "CRITICAL" + colorReset
	case signal.Red:
		return colorRed + "DANGER" + colorReset
	case signal.Yellow:
		return colorYellow + "WARNING" + colorReset
	case signal.Green:
		return colorGreen + "OK" + colorReset
	default:
		return "UNKNOWN"
	}
}

// signalColor returns the ANSI color for a signal light.
func signalColor(l signal.Light) string {
	switch l {
	case signal.Purple:
		return colorPurple
	case signal.Red:
		return colorRed
	case signal.Yellow:
		return colorYellow
	case signal.Green:
		return colorGreen
	default:
		return ""
	}
}

// progressBar builds a text progress bar.
func progressBar(usedRatio float64, width int) string {
	filled := int(usedRatio * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return "[" + strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", width-filled) + "]"
}

// RenderStatus formats status output as text or JSON.
func RenderStatus(data StatusOutput, asJSON bool) string {
	if asJSON {
		data.SchemaVersion = schemaVer
		data.Tool = toolName
		data.ToolVersion = toolVersion
		data.Timestamp = now()
		data.Platform = platform()
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": %q}`, err.Error())
		}
		return string(b)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Kill-line: %s\n\n", units.FormatSize(data.KillLineBytes)))

	for _, d := range data.Drives {
		var usedRatio float64
		if d.TotalBytes > 0 {
			usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
		}
		bar := progressBar(usedRatio, 20)
		// Color the progress bar based on signal light
		coloredBar := signalColor(d.Signal.Light) + bar + colorReset
		label := signalLabel(d.Signal.Light)
		sb.WriteString(fmt.Sprintf("%-6s %s  %s / %s  %s\n",
			d.Path, coloredBar,
			units.FormatSize(d.FreeBytes),
			units.FormatSize(d.TotalBytes),
			label,
		))
	}
	return sb.String()
}

// RenderScan formats scan output as text or JSON.
func RenderScan(data ScanOutput, asJSON bool) string {
	if asJSON {
		data.SchemaVersion = schemaVer
		data.Tool = toolName
		data.ToolVersion = toolVersion
		data.Timestamp = now()
		data.Platform = platform()
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": %q}`, err.Error())
		}
		return string(b)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Scan: %s  (engine: %s, coverage: %.0f%%, %dms)\n",
		data.Data.RootPath, data.Data.EngineName,
		data.Data.ScanCoverage*100, data.Data.DurationMs))
	sb.WriteString(fmt.Sprintf("Total: %s  Free: %s  Used: %s\n\n",
		units.FormatSize(data.Data.TotalBytes),
		units.FormatSize(data.Data.FreeBytes),
		units.FormatSize(data.Data.UsedBytes)))

	// Header
	sb.WriteString(fmt.Sprintf("%-12s  %-5s  %s\n", "SIZE", "KIND", "PATH"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, e := range data.Data.Entries {
		kind := "file"
		if e.IsDir {
			kind = "dir"
		}
		sb.WriteString(fmt.Sprintf("%-12s  %-5s  %s\n",
			units.FormatSize(e.SizeBytes), kind, e.Path))
	}
	return sb.String()
}

// RenderHunt formats hunt output as text or JSON.
func RenderHunt(data HuntOutput, asJSON bool) string {
	if asJSON {
		data.SchemaVersion = schemaVer
		data.Tool = toolName
		data.ToolVersion = toolVersion
		data.Timestamp = now()
		data.Platform = platform()
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": %q}`, err.Error())
		}
		return string(b)
	}

	var sb strings.Builder
	sb.WriteString("Prey List\n")
	sb.WriteString(strings.Repeat("=", 70) + "\n\n")

	for _, p := range data.Data.Prey {
		tag := riskTag(p.Risk)
		sb.WriteString(fmt.Sprintf("%s  %s  %s\n", tag,
			units.FormatSize(p.SizeBytes), p.Path))
		sb.WriteString(fmt.Sprintf("  Kind: %s  Description: %s\n", p.Kind, p.Description))
		if p.Action.Type == "command" {
			sb.WriteString(fmt.Sprintf("  Cleanup: %s\n", p.Action.Command))
		} else if p.Action.Hint != "" {
			sb.WriteString(fmt.Sprintf("  Hint: %s\n", p.Action.Hint))
		}
		sb.WriteString("\n")
	}

	s := data.Data.Summary
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	sb.WriteString(fmt.Sprintf("Total: %d prey, %s reclaimable\n",
		s.TotalPrey, units.FormatSize(s.TotalBytes)))
	sb.WriteString(fmt.Sprintf("  SAFE: %d (%s)  CAUTION: %d (%s)  DANGER: %d (%s)\n",
		s.SafeCount, units.FormatSize(s.SafeBytes),
		s.CautionCount, units.FormatSize(s.CautionBytes),
		s.DangerCount, units.FormatSize(s.DangerBytes)))

	return sb.String()
}

func riskTag(r hunter.Risk) string {
	switch r {
	case hunter.RiskSafe:
		return "[SAFE]"
	case hunter.RiskCaution:
		return "[CAUTION]"
	case hunter.RiskDanger:
		return "[DANGER]"
	default:
		return "[UNKNOWN]"
	}
}

// RenderClean formats clean output as text or JSON.
func RenderClean(data CleanOutput, asJSON bool) string {
	if asJSON {
		data.SchemaVersion = schemaVer
		data.Tool = toolName
		data.ToolVersion = toolVersion
		data.Timestamp = now()
		data.Platform = platform()
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": %q}`, err.Error())
		}
		return string(b)
	}

	var sb strings.Builder
	sb.WriteString("Cleanup Results\n")
	sb.WriteString(strings.Repeat("=", 70) + "\n\n")

	for _, c := range data.Data.Cleaned {
		sb.WriteString(fmt.Sprintf("  %s  %s  (%s, freed %s)\n",
			c.Kind, c.Path, c.SizeHuman, units.FormatSize(c.FreedBytes)))
	}

	if len(data.Data.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, e := range data.Data.Errors {
			sb.WriteString(fmt.Sprintf("  ! %s\n", e))
		}
	}

	sb.WriteString(fmt.Sprintf("\nTotal freed: %s\n", data.Data.FreedHuman))
	return sb.String()
}
