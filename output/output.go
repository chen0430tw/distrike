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

// ToolVersion is set from cmd.Version at init time.
var ToolVersion = "dev"

const (
	toolName  = "distrike"
	schemaVer = "1.0"
)

// VDiskEntry represents a virtual disk found on the system.
type VDiskEntry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

// StatusOutput is the JSON schema for distrike status.
type StatusOutput struct {
	SchemaVersion string        `json:"schema_version"`
	Tool          string        `json:"tool"`
	ToolVersion   string        `json:"tool_version"`
	Timestamp     string        `json:"timestamp"`
	Platform      string        `json:"platform"`
	KillLineBytes int64         `json:"kill_line_bytes"`
	Drives        []DriveOutput `json:"drives"`
	VDisks        []VDiskEntry  `json:"vdisks,omitempty"`
}

// DriveOutput is the per-drive section of status output.
type DriveOutput struct {
	Path       string        `json:"path"`
	FSType     string        `json:"fs_type,omitempty"`
	TotalBytes int64         `json:"total_bytes"`
	FreeBytes  int64         `json:"free_bytes"`
	UsedBytes  int64         `json:"used_bytes"`
	Signal     signal.Signal `json:"signal"`
	Removable  bool          `json:"removable"`
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

// 24-bit RGB color codes
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[38;2;50;205;50m"        // Lime green rgb(50,205,50)
	colorYellow = "\033[38;2;255;193;7m"        // Claude Code warning amber
	colorRed    = "\033[38;2;218;38;38m"        // Windows Explorer capacity-bar red #DA2626
	colorPurple = "\033[38;2;147;51;234m"       // Claude Code purple
)

// signalName returns the plain text name for a signal light.
func signalName(l signal.Light) string {
	switch l {
	case signal.Purple:
		return "CRITICAL"
	case signal.Red:
		return "DANGER"
	case signal.Yellow:
		return "WARNING"
	case signal.Green:
		return "OK"
	default:
		return "UNKNOWN"
	}
}

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

// shortenPath truncates a path to maxLen, keeping head + ... + tail.
// Always hard-truncates when len(p) > maxLen, even for small maxLen.
func shortenPath(p string, maxLen int) string {
	if len(p) <= maxLen {
		return p
	}
	if maxLen <= 3 {
		return p[:maxLen]
	}
	if maxLen < 10 {
		return p[:maxLen-3] + "..."
	}
	tailLen := maxLen / 3
	if tailLen > 30 {
		tailLen = 30
	}
	headLen := maxLen - tailLen - 3 // 3 for "..."
	if headLen < 1 {
		headLen = 1
	}
	return p[:headLen] + "..." + p[len(p)-tailLen:]
}

// progressBar builds a text progress bar.
// At width=40, resolution is 2.5% per cell.
func progressBar(usedRatio float64, width int) string {
	filled := int(usedRatio*float64(width) + 0.5) // round
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
		data.ToolVersion = ToolVersion
		data.Timestamp = now()
		data.Platform = platform()
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Sprintf(`{"error": %q}`, err.Error())
		}
		return string(b)
	}

	const sigW = 22 // fits "CRITICAL[USB][ReFS]" + padding
	const pctW = 8  // fits "100.0%" + padding
	const freeW = 11
	const totalW = 11
	const minBarW = 15
	const minDrvW = 4

	// Fixed overhead per row (separators + fixed-width columns, excluding drv and bar).
	const fixedOverhead = 1 + 1 + pctW + 1 + freeW + 1 + totalW + 1 + sigW

	// Determine longest drive path needed.
	drvW := minDrvW
	for _, d := range data.Drives {
		p := strings.TrimRight(d.Path, `\`)
		if len(p) > drvW {
			drvW = len(p)
		}
	}

	// Fit table within terminal width.
	// Inner width: (drvW+2) + (barW+2) + fixedOverhead; outer border adds 2.
	termW := TermWidth()
	barW := 30
	for barW > minBarW {
		w := (drvW + 2) + (barW + 1 + 1) + fixedOverhead
		if w+2 <= termW {
			break
		}
		barW -= 2
	}
	for drvW > minDrvW {
		w := (drvW + 2) + (barW + 1 + 1) + fixedOverhead
		if w+2 <= termW {
			break
		}
		drvW--
	}

	drvCol := drvW + 2 // +2 for border spaces

	// Columns: Drive(drvCol) | Bar(barW+1) | Used%(pctW) | Free(freeW) | Total(totalW) | Signal(sigW)
	w := drvCol + 1 + barW + 1 + 1 + pctW + 1 + freeW + 1 + totalW + 1 + sigW

	var sb strings.Builder

	// Header
	title := fmt.Sprintf(" Distrike %s", ToolVersion)
	killStr := fmt.Sprintf("Kill-line: %s ", units.FormatSize(data.KillLineBytes))
	padding := w - len(title) - len(killStr)
	if padding < 1 {
		padding = 1
	}
	sb.WriteString("╭" + strings.Repeat("─", w) + "╮\n")
	sb.WriteString("│" + title + strings.Repeat(" ", padding) + killStr + "│\n")
	sb.WriteString("├" + strings.Repeat("─", drvCol) + "┬" + strings.Repeat("─", barW+1) + "┬" + strings.Repeat("─", pctW) + "┬" + strings.Repeat("─", freeW) + "┬" + strings.Repeat("─", totalW) + "┬" + strings.Repeat("─", sigW) + "┤\n")
	sb.WriteString(fmt.Sprintf("│ %-*s │ %-*s │ %6s │ %*s │ %*s │ %-*s│\n",
		drvW, "Drv", barW-1, "Usage", "Used%", freeW-2, "Free", totalW-2, "Total", sigW-1, "Signal"))
	sb.WriteString("├" + strings.Repeat("─", drvCol) + "┼" + strings.Repeat("─", barW+1) + "┼" + strings.Repeat("─", pctW) + "┼" + strings.Repeat("─", freeW) + "┼" + strings.Repeat("─", totalW) + "┼" + strings.Repeat("─", sigW) + "┤\n")

	// Drive rows — manual assembly to avoid ANSI codes breaking fmt width
	for _, d := range data.Drives {
		var usedRatio float64
		if d.TotalBytes > 0 {
			usedRatio = float64(d.UsedBytes) / float64(d.TotalBytes)
		}
		bar := progressBar(usedRatio, barW-3) // -3: barW minus [] brackets and space
		pct := fmt.Sprintf("%6s", fmt.Sprintf("%.1f%%", usedRatio*100))
		free := fmt.Sprintf("%*s", freeW-2, units.FormatSize(d.FreeBytes))
		total := fmt.Sprintf("%*s", totalW-2, units.FormatSize(d.TotalBytes))

		sigText := signalName(d.Signal.Light)
		if d.Removable {
			sigText += "[USB]"
		}
		if d.FSType != "" && !strings.EqualFold(d.FSType, "NTFS") {
			sigText += "[" + d.FSType + "]"
		}
		paddedSig := fmt.Sprintf("%-*s", sigW-1, sigText)

		// Truncate path if it exceeds the column width.
		path := strings.TrimRight(d.Path, `\`)
		drv := fmt.Sprintf("%-*s", drvW, shortenPath(path, drvW))
		c := signalColor(d.Signal.Light)

		sb.WriteString("│ " + drv + " │ " + c + bar + colorReset + " │ " + pct + " │ " + free + " │ " + total + " │ " + c + paddedSig + colorReset + "│\n")
	}

	sb.WriteString("╰" + strings.Repeat("─", drvCol) + "┴" + strings.Repeat("─", barW+1) + "┴" + strings.Repeat("─", pctW) + "┴" + strings.Repeat("─", freeW) + "┴" + strings.Repeat("─", totalW) + "┴" + strings.Repeat("─", sigW) + "╯\n")

	// Virtual disks section
	if len(data.VDisks) > 0 {
		sb.WriteString("\n Virtual Disks:\n")
		for _, v := range data.VDisks {
			short := shortenPath(v.Path, 50)
			sb.WriteString(fmt.Sprintf("   %-20s %10s   %s\n", v.Name, units.FormatSize(v.SizeBytes), short))
		}
	} else {
		sb.WriteString("\n Virtual Disks: none\n")
	}

	// Signal legend
	sb.WriteString("\n PURPLE < 1 GB │ RED < kill-line │ YELLOW < kill-line×1.5 │ GREEN = safe\n")
	return sb.String()
}

// RenderScan formats scan output as text or JSON.
func RenderScan(data ScanOutput, asJSON bool) string {
	if asJSON {
		data.SchemaVersion = schemaVer
		data.Tool = toolName
		data.ToolVersion = ToolVersion
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
		data.ToolVersion = ToolVersion
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
		cosmeticTag := ""
		if p.Cosmetic {
			cosmeticTag = " [cosmetic]"
		}
		sb.WriteString(fmt.Sprintf("%s  %s  %s%s\n", tag,
			units.FormatSize(p.SizeBytes), p.Path, cosmeticTag))
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
		data.ToolVersion = ToolVersion
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
