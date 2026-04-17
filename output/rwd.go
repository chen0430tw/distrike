package output

// Responsive table template inspired by Bootstrap's breakpoint system.
//
// Breakpoints (80-col-first, analogous to Bootstrap's mobile-first):
//
//	xs  : <40   cols   — phone-in-pocket / tmux tiny pane
//	sm  : ≥40   cols   — narrow pane
//	md  : ≥80   cols   — classic VT100 width (baseline)
//	lg  : ≥120  cols   — modern laptop
//	xl  : ≥160  cols   — wide monitor
//	xxl : ≥200  cols   — ultrawide
//
// Columns declare VisibleFrom: a column appears at that breakpoint and above.
// This inverts Bootstrap's d-{bp}-none utility — columns opt in from their
// minimum breakpoint rather than opt out below a breakpoint.
//
// Layout algorithm:
//  1. Filter columns: drop those whose VisibleFrom > current breakpoint.
//  2. Cap termW at Container.MaxWidth[bp] if set (matches Bootstrap container
//     max-widths — prevents stretching absurdly on ultrawide terminals).
//  3. Shrink flex columns (most-slack first) until the row fits.
//  4. Safety drop: if Phase 3 can't fit, drop the column with highest
//     VisibleFrom — the most "optional" one. Columns with VisibleFrom == BpXS
//     are mandatory and are never dropped.

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Breakpoint identifies a terminal width bucket.
type Breakpoint int

const (
	BpXS  Breakpoint = iota // <40
	BpSM                    // ≥40
	BpMD                    // ≥80
	BpLG                    // ≥120
	BpXL                    // ≥160
	BpXXL                   // ≥200
)

var bpMinWidth = [...]int{BpXS: 0, BpSM: 40, BpMD: 80, BpLG: 120, BpXL: 160, BpXXL: 200}
var bpName = [...]string{"xs", "sm", "md", "lg", "xl", "xxl"}

func (b Breakpoint) String() string {
	if int(b) < 0 || int(b) >= len(bpName) {
		return "?"
	}
	return bpName[b]
}

// DetectBreakpoint returns the largest breakpoint whose min-width is ≤ termW.
func DetectBreakpoint(termW int) Breakpoint {
	bp := BpXS
	for i, min := range bpMinWidth {
		if termW >= min {
			bp = Breakpoint(i)
		}
	}
	return bp
}

// Alignment controls left/right justification within a column's width.
type Alignment int

const (
	AlignLeft Alignment = iota
	AlignRight
)

// Column describes one logical column. Natural/Min drive sizing, VisibleFrom
// drives breakpoint gating, Align controls cell justification.
type Column struct {
	Name        string
	Natural     int
	Min         int
	VisibleFrom Breakpoint
	Align       Alignment
}

func (c Column) flex() bool { return c.Min > 0 && c.Min < c.Natural }

// Container caps rendered width per breakpoint. Mirrors Bootstrap .container
// max-widths. A missing / zero entry means "use full termW".
type Container struct {
	MaxWidth map[Breakpoint]int
}

func (c Container) effectiveWidth(termW int, bp Breakpoint) int {
	if c.MaxWidth == nil {
		return termW
	}
	cap, ok := c.MaxWidth[bp]
	if !ok || cap <= 0 || cap >= termW {
		return termW
	}
	return cap
}

// Table is the renderer input.
type Table struct {
	Columns   []Column
	Container Container
	NumRows   int

	// RenderCell produces the display value for (row, origCol) at the final
	// width assigned after layout. May embed ANSI escapes.
	RenderCell func(row, col, width int) string

	// TSVCell returns a pipe-safe raw value: no ANSI, no truncation,
	// full precision. Required for TSV output.
	TSVCell func(row, col int) string
}

// RenderTable returns the framed-Unicode table at the given terminal width.
func (t Table) RenderTable(termW int) string {
	widths, origIdx := t.layout(termW)
	n := len(widths)

	var sb strings.Builder

	sb.WriteString("╭")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < n-1 {
			sb.WriteString("┬")
		}
	}
	sb.WriteString("╮\n")

	sb.WriteString("│")
	for i, w := range widths {
		col := t.Columns[origIdx[i]]
		sb.WriteString(" " + fit(col.Name, w, col.Align) + " │")
	}
	sb.WriteString("\n")

	sb.WriteString("├")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < n-1 {
			sb.WriteString("┼")
		}
	}
	sb.WriteString("┤\n")

	for row := 0; row < t.NumRows; row++ {
		sb.WriteString("│")
		for i, w := range widths {
			col := t.Columns[origIdx[i]]
			sb.WriteString(" " + fit(t.RenderCell(row, origIdx[i], w), w, col.Align) + " │")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("╰")
	for i, w := range widths {
		sb.WriteString(strings.Repeat("─", w+2))
		if i < n-1 {
			sb.WriteString("┴")
		}
	}
	sb.WriteString("╯\n")

	return sb.String()
}

// RenderTSV returns pipe-safe tab-separated output (header + rows).
// No frames, no ANSI, no truncation, full precision.
func (t Table) RenderTSV() string {
	var sb strings.Builder
	for i, c := range t.Columns {
		if i > 0 {
			sb.WriteByte('\t')
		}
		sb.WriteString(c.Name)
	}
	sb.WriteByte('\n')
	for row := 0; row < t.NumRows; row++ {
		for i := range t.Columns {
			if i > 0 {
				sb.WriteByte('\t')
			}
			sb.WriteString(t.TSVCell(row, i))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// layout runs breakpoint filter → container cap → shrink → safety-drop.
// Returns final widths and original-column indices for the kept columns.
func (t Table) layout(termW int) (widths []int, origIdx []int) {
	bp := DetectBreakpoint(termW)
	effW := t.Container.effectiveWidth(termW, bp)

	widths = make([]int, 0, len(t.Columns))
	origIdx = make([]int, 0, len(t.Columns))
	for i, c := range t.Columns {
		if c.VisibleFrom <= bp {
			widths = append(widths, c.Natural)
			origIdx = append(origIdx, i)
		}
	}

	for {
		for assembledWidth(widths) > effW {
			shrinkIdx := -1
			maxSlack := 0
			for i, w := range widths {
				col := t.Columns[origIdx[i]]
				if !col.flex() {
					continue
				}
				slack := w - col.Min
				if slack > maxSlack {
					maxSlack = slack
					shrinkIdx = i
				}
			}
			if shrinkIdx < 0 {
				break
			}
			widths[shrinkIdx]--
		}
		if assembledWidth(widths) <= effW {
			return
		}
		dropIdx := -1
		var maxBp Breakpoint = -1
		for i, oi := range origIdx {
			if t.Columns[oi].VisibleFrom > maxBp {
				maxBp = t.Columns[oi].VisibleFrom
				dropIdx = i
			}
		}
		if dropIdx < 0 || maxBp <= BpXS {
			return
		}
		widths = append(widths[:dropIdx], widths[dropIdx+1:]...)
		origIdx = append(origIdx[:dropIdx], origIdx[dropIdx+1:]...)
	}
}

// assembledWidth counts visible cells for "│ W │ W │ ... │".
func assembledWidth(widths []int) int {
	w := 1
	for _, x := range widths {
		w += x + 3
	}
	return w
}

// displayWidth returns visual cell count of s, ignoring ANSI CSI escapes.
// Counts each rune as 1 cell (not East-Asian-Width aware).
func displayWidth(s string) int {
	w, inEsc := 0, false
	for _, r := range s {
		if inEsc {
			if r == 'm' || r == 'K' || r == 'J' || r == 'H' {
				inEsc = false
			}
			continue
		}
		if r == 0x1b {
			inEsc = true
			continue
		}
		w++
	}
	return w
}

// fit pads or truncates s to exactly w cells, preserving ANSI escapes.
func fit(s string, w int, a Alignment) string {
	cur := displayWidth(s)
	if cur == w {
		return s
	}
	if cur < w {
		pad := strings.Repeat(" ", w-cur)
		if a == AlignRight {
			return pad + s
		}
		return s + pad
	}
	return truncateToWidth(s, w)
}

// truncateToWidth truncates to w cells, appending "…" and preserving any
// trailing ANSI escapes (e.g. "\033[0m") so color state doesn't leak into
// downstream output.
func truncateToWidth(s string, w int) string {
	if w < 1 {
		return ""
	}
	var out []rune
	cells := 0
	inEsc := false
	truncated := false
	for _, r := range s {
		if r == 0x1b {
			out = append(out, r)
			inEsc = true
			continue
		}
		if inEsc {
			out = append(out, r)
			if r == 'm' || r == 'K' || r == 'J' || r == 'H' {
				inEsc = false
			}
			continue
		}
		if truncated {
			continue
		}
		if cells >= w-1 {
			out = append(out, '…')
			truncated = true
			continue
		}
		out = append(out, r)
		cells++
	}
	if !truncated {
		out = append(out, '…')
	}
	return string(out)
}

// TruncPath shortens p to w cells, keeping leading 3 chars + "…" + tail.
func TruncPath(p string, w int) string {
	if utf8.RuneCountInString(p) <= w {
		return p
	}
	if w < 5 {
		return truncateToWidth(p, w)
	}
	runes := []rune(p)
	head := 3
	tail := w - head - 1
	return string(runes[:head]) + "…" + string(runes[len(runes)-tail:])
}

// Hr returns a horizontal rule of the given character, sized to termW.
// Used by list-style renderers (hunt, clean) that aren't full tables but
// still want to respect terminal width.
func Hr(ch string, termW int) string {
	if termW < 10 {
		termW = 10
	}
	if termW > 120 {
		termW = 120
	}
	return strings.Repeat(ch, termW)
}

// debugBannerUnused silences vet on fmt imports when layoutResult formatting
// is removed. Kept as a stub to document the intent.
var _ = fmt.Sprintf
