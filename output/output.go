package output

import (
	"encoding/json"
	"fmt"
	"os"
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

// 24-bit RGB color codes. Stripped at init() only when NO_COLOR is set;
// TTY detection is NOT used here because --format=table is an explicit user
// request to render the framed table even through a pipe, and colors are
// part of that rendering. Auto-detection of TTY happens at format-resolution
// time (ResolveAuto in format.go), not at color emission.
var (
	colorReset  = "\033[0m"
	colorGreen  = "\033[38;2;50;205;50m"        // Lime green rgb(50,205,50)
	colorYellow = "\033[38;2;255;193;7m"        // Claude Code warning amber
	colorRed    = "\033[38;2;218;38;38m"        // Windows Explorer capacity-bar red #DA2626
	colorPurple = "\033[38;2;147;51;234m"       // Claude Code purple
)

func init() {
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		colorReset, colorGreen, colorYellow, colorRed, colorPurple = "", "", "", "", ""
	}
}

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

// progressBar builds a text progress bar using two glyphs:
//
//	frac >= 0.5: █ (U+2588, full block, signal-color solid)
//	frac <  0.5: ░ (U+2591, light shade — mesh track)
//
// Both characters are in Windows Terminal's AtlasEngine built-in glyph
// range (U+2500-259F), so they're drawn by WT's own pixel code — not via
// the font — guaranteeing pixel-perfect cell alignment.
//
// We explored adding ▌ (U+258C, left half block) as a partial-fill indicator
// for finer granularity, but ▌'s right half renders as terminal bg while
// adjacent ░ cells render as screen-absolute dither — visible gap at the
// ▌→░ boundary. See docs/cascadia-shade-deconstruction.md for why a
// seamless partial cell is physically impossible under WT's rendering
// architecture. Binary ends up as the cleanest compromise.
//
// Precision: ±1.7% for a 30-cell bar. Plenty for disk-status visualization
// where the exact percentage is shown in the adjacent Used% column.
//
// trackBg, if non-empty, wraps the unfilled region with an ANSI SGR
// background so mesh dots render on a signal-tinted track.
func progressBar(usedRatio float64, width int, trackBg string) string {
	if width < 1 {
		return "[]"
	}
	if usedRatio < 0 {
		usedRatio = 0
	}
	if usedRatio > 1 {
		usedRatio = 1
	}
	const bgReset = "\033[49m"
	var filled, unfilled strings.Builder
	for i := 0; i < width; i++ {
		frac := usedRatio*float64(width) - float64(i)
		if frac >= 0.5 {
			filled.WriteString("\u2588") // █ FULL
		} else {
			unfilled.WriteString("\u2591") // ░ LIGHT SHADE
		}
	}
	var sb strings.Builder
	sb.WriteByte('[')
	sb.WriteString(filled.String())
	if unfilled.Len() > 0 {
		if trackBg != "" {
			sb.WriteString(trackBg)
		}
		sb.WriteString(unfilled.String())
		if trackBg != "" {
			sb.WriteString(bgReset)
		}
	}
	sb.WriteByte(']')
	return sb.String()
}


// RenderStatus formats status output per the requested Format.
func RenderStatus(data StatusOutput, format Format) string {
	if format == FormatJSON {
		return renderJSON(func() interface{} {
			data.SchemaVersion = schemaVer
			data.Tool = toolName
			data.ToolVersion = ToolVersion
			data.Timestamp = now()
			data.Platform = platform()
			return data
		})
	}
	tbl := buildStatusTable(data)
	switch ResolveAuto(format) {
	case FormatTSV:
		return tbl.RenderTSV()
	default: // FormatTable
		var sb strings.Builder
		sb.WriteString(tbl.RenderTable(TermWidth()))
		if len(data.VDisks) > 0 {
			sb.WriteString("\n Virtual Disks:\n")
			for _, v := range data.VDisks {
				short := shortenPath(v.Path, 50)
				sb.WriteString(fmt.Sprintf("   %-20s %10s   %s\n", v.Name, units.FormatSize(v.SizeBytes), short))
			}
		} else {
			sb.WriteString("\n Virtual Disks: none\n")
		}
		sb.WriteString("\n PURPLE < 1 GB │ RED < kill-line │ YELLOW < kill-line×1.5 │ GREEN = safe\n")
		return sb.String()
	}
}

// buildStatusTable constructs the responsive Table for status output.
// Column visibility gated by breakpoint (Bootstrap-style):
//
//	xs+: Drv, Signal         (mandatory)
//	sm+: Usage bar, Free
//	md+: Used%
//	lg+: Total
func buildStatusTable(data StatusOutput) Table {
	maxPath, maxSig := 3, 6
	for _, d := range data.Drives {
		p := strings.TrimRight(d.Path, `\`)
		if n := len([]rune(p)); n > maxPath {
			maxPath = n
		}
		if n := len([]rune(statusSignalText(d))); n > maxSig {
			maxSig = n
		}
	}
	if maxPath > 30 {
		maxPath = 30
	}

	cols := []Column{
		{Name: "Drv", Natural: maxPath, Min: 4, VisibleFrom: BpXS, Align: AlignLeft},
		// Usage Natural=32: 30 inner cells, 3.33% per cell. Width=35 (33 inner)
		// was tried to align █→░ boundaries with WT's 4-cell dither tiles —
		// no visible improvement in seam appearance, and the wider bar pushed
		// the whole table longer. Rolled back to 30 inner as the balance
		// between precision and column footprint. Shrinks to Min=10 at narrow.
		{Name: "Usage", Natural: 32, Min: 10, VisibleFrom: BpSM, Align: AlignLeft},
		{Name: "Used%", Natural: 6, Min: 6, VisibleFrom: BpMD, Align: AlignRight},
		{Name: "Free", Natural: 9, Min: 9, VisibleFrom: BpSM, Align: AlignRight},
		{Name: "Total", Natural: 9, Min: 9, VisibleFrom: BpLG, Align: AlignRight},
		{Name: "Signal", Natural: maxSig, Min: 6, VisibleFrom: BpXS, Align: AlignLeft},
	}
	// Container caps raised to accommodate wider Usage bar without over-stretching.
	container := Container{MaxWidth: map[Breakpoint]int{BpXL: 160, BpXXL: 180}}

	return Table{
		Columns:   cols,
		Container: container,
		NumRows:   len(data.Drives),
		RenderCell: func(row, col, width int) string {
			d := data.Drives[row]
			var ratio float64
			if d.TotalBytes > 0 {
				ratio = float64(d.UsedBytes) / float64(d.TotalBytes)
			}
			switch cols[col].Name {
			case "Drv":
				return TruncPath(strings.TrimRight(d.Path, `\`), width)
			case "Usage":
				inner := width - 2
				if inner < 1 {
					inner = 1
				}
				return signalColor(d.Signal.Light) + progressBar(ratio, inner, "") + colorReset
			case "Used%":
				return fmt.Sprintf("%.1f%%", ratio*100)
			case "Free":
				return units.FormatSize(d.FreeBytes)
			case "Total":
				return units.FormatSize(d.TotalBytes)
			case "Signal":
				return signalColor(d.Signal.Light) + statusSignalText(d) + colorReset
			}
			return ""
		},
		TSVCell: func(row, col int) string {
			d := data.Drives[row]
			var ratio float64
			if d.TotalBytes > 0 {
				ratio = float64(d.UsedBytes) / float64(d.TotalBytes)
			}
			switch cols[col].Name {
			case "Drv":
				return strings.TrimRight(d.Path, `\`)
			case "Usage", "Used%":
				return fmt.Sprintf("%.4f", ratio)
			case "Free":
				return fmt.Sprintf("%d", d.FreeBytes)
			case "Total":
				return fmt.Sprintf("%d", d.TotalBytes)
			case "Signal":
				return statusSignalText(d)
			}
			return ""
		},
	}
}

// statusSignalText returns the signal name with [USB] and [FS] annotations.
func statusSignalText(d DriveOutput) string {
	t := signalName(d.Signal.Light)
	if d.Removable {
		t += "[USB]"
	}
	if d.FSType != "" && !strings.EqualFold(d.FSType, "NTFS") {
		t += "[" + d.FSType + "]"
	}
	return t
}

// renderJSON is a shared helper that stamps schema/version/timestamp/platform
// onto the passed-through value and returns indented JSON.
func renderJSON(stamp func() interface{}) string {
	v := stamp()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(b)
}

// RenderScan formats scan output per the requested Format.
func RenderScan(data ScanOutput, format Format) string {
	if format == FormatJSON {
		return renderJSON(func() interface{} {
			data.SchemaVersion = schemaVer
			data.Tool = toolName
			data.ToolVersion = ToolVersion
			data.Timestamp = now()
			data.Platform = platform()
			return data
		})
	}
	tbl := buildScanTable(data)
	switch ResolveAuto(format) {
	case FormatTSV:
		return tbl.RenderTSV()
	default: // FormatTable
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Scan: %s  (engine: %s, coverage: %.0f%%, %dms)\n",
			data.Data.RootPath, data.Data.EngineName,
			data.Data.ScanCoverage*100, data.Data.DurationMs))
		sb.WriteString(fmt.Sprintf("Total: %s  Free: %s  Used: %s\n\n",
			units.FormatSize(data.Data.TotalBytes),
			units.FormatSize(data.Data.FreeBytes),
			units.FormatSize(data.Data.UsedBytes)))
		sb.WriteString(tbl.RenderTable(TermWidth()))
		return sb.String()
	}
}

// buildScanTable constructs the responsive Table for scan output.
// Column visibility:
//
//	xs+: Size, Path (mandatory)
//	sm+: Kind
func buildScanTable(data ScanOutput) Table {
	maxPath := 4
	for _, e := range data.Data.Entries {
		if n := len([]rune(e.Path)); n > maxPath {
			maxPath = n
		}
	}
	if maxPath > 60 {
		maxPath = 60
	}

	cols := []Column{
		{Name: "Size", Natural: 9, Min: 9, VisibleFrom: BpXS, Align: AlignRight},
		{Name: "Kind", Natural: 4, Min: 4, VisibleFrom: BpSM, Align: AlignLeft},
		{Name: "Path", Natural: maxPath, Min: 10, VisibleFrom: BpXS, Align: AlignLeft},
	}

	return Table{
		Columns: cols,
		NumRows: len(data.Data.Entries),
		RenderCell: func(row, col, width int) string {
			e := data.Data.Entries[row]
			switch cols[col].Name {
			case "Size":
				return units.FormatSize(e.SizeBytes)
			case "Kind":
				if e.IsDir {
					return "dir"
				}
				return "file"
			case "Path":
				return TruncPath(e.Path, width)
			}
			return ""
		},
		TSVCell: func(row, col int) string {
			e := data.Data.Entries[row]
			switch cols[col].Name {
			case "Size":
				return fmt.Sprintf("%d", e.SizeBytes)
			case "Kind":
				if e.IsDir {
					return "dir"
				}
				return "file"
			case "Path":
				return e.Path
			}
			return ""
		},
	}
}

// RenderHunt formats hunt output per the requested Format.
// Hunt is a list-style report (multi-line per prey), not a table; TSV mode
// flattens each prey to one row with tab-separated fields.
func RenderHunt(data HuntOutput, format Format) string {
	if format == FormatJSON {
		return renderJSON(func() interface{} {
			data.SchemaVersion = schemaVer
			data.Tool = toolName
			data.ToolVersion = ToolVersion
			data.Timestamp = now()
			data.Platform = platform()
			return data
		})
	}
	if ResolveAuto(format) == FormatTSV {
		return renderHuntTSV(data)
	}

	termW := TermWidth()
	var sb strings.Builder
	sb.WriteString("Prey List\n")
	sb.WriteString(Hr("=", termW) + "\n\n")

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
	sb.WriteString(Hr("-", termW) + "\n")
	sb.WriteString(fmt.Sprintf("Total: %d prey, %s reclaimable\n",
		s.TotalPrey, units.FormatSize(s.TotalBytes)))
	sb.WriteString(fmt.Sprintf("  SAFE: %d (%s)  CAUTION: %d (%s)  DANGER: %d (%s)\n",
		s.SafeCount, units.FormatSize(s.SafeBytes),
		s.CautionCount, units.FormatSize(s.CautionBytes),
		s.DangerCount, units.FormatSize(s.DangerBytes)))

	return sb.String()
}

func renderHuntTSV(data HuntOutput) string {
	var sb strings.Builder
	sb.WriteString("risk\tsize_bytes\tkind\tpath\tdescription\tcommand\thint\tcosmetic\n")
	for _, p := range data.Data.Prey {
		cmd := ""
		hint := ""
		if p.Action.Type == "command" {
			cmd = p.Action.Command
		}
		if p.Action.Hint != "" {
			hint = p.Action.Hint
		}
		sb.WriteString(fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s\t%s\t%v\n",
			riskLabel(p.Risk), p.SizeBytes, p.Kind, p.Path,
			sanitizeTab(p.Description), sanitizeTab(cmd), sanitizeTab(hint), p.Cosmetic))
	}
	return sb.String()
}

// sanitizeTab replaces tabs and newlines in TSV field values.
func sanitizeTab(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// riskLabel returns the plain text risk label used in TSV output (no brackets).
func riskLabel(r hunter.Risk) string {
	switch r {
	case hunter.RiskSafe:
		return "SAFE"
	case hunter.RiskCaution:
		return "CAUTION"
	case hunter.RiskDanger:
		return "DANGER"
	default:
		return "UNKNOWN"
	}
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

// RenderClean formats clean output per the requested Format.
func RenderClean(data CleanOutput, format Format) string {
	if format == FormatJSON {
		return renderJSON(func() interface{} {
			data.SchemaVersion = schemaVer
			data.Tool = toolName
			data.ToolVersion = ToolVersion
			data.Timestamp = now()
			data.Platform = platform()
			return data
		})
	}
	if ResolveAuto(format) == FormatTSV {
		return renderCleanTSV(data)
	}

	termW := TermWidth()
	var sb strings.Builder
	sb.WriteString("Cleanup Results\n")
	sb.WriteString(Hr("=", termW) + "\n\n")

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

func renderCleanTSV(data CleanOutput) string {
	var sb strings.Builder
	sb.WriteString("kind\tpath\tsize_bytes\tfreed_bytes\trisk\tcommand\n")
	for _, c := range data.Data.Cleaned {
		sb.WriteString(fmt.Sprintf("%s\t%s\t%d\t%d\t%s\t%s\n",
			c.Kind, c.Path, c.SizeBytes, c.FreedBytes, c.Risk, sanitizeTab(c.Command)))
	}
	if len(data.Data.Errors) > 0 {
		for _, e := range data.Data.Errors {
			sb.WriteString(fmt.Sprintf("ERROR\t%s\t0\t0\t\t\n", sanitizeTab(e)))
		}
	}
	return sb.String()
}
