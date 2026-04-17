package output

import (
	"os"

	"golang.org/x/term"
)

// useColor is set once at package init. When false, color constants
// are replaced with empty strings so rendered output stays ANSI-free
// (required when stdout is piped, redirected, or attached to a non-TTY
// like SSH without PTY).
var useColor = detectColor()

// detectColor follows the widely-adopted order:
//  1. NO_COLOR (https://no-color.org/) — set to any non-empty value disables colors
//  2. FORCE_COLOR — set to any non-empty value forces colors regardless of TTY
//  3. stdout must be a terminal
func detectColor() bool {
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		return false
	}
	if v, ok := os.LookupEnv("FORCE_COLOR"); ok && v != "" {
		return true
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// UseColor reports whether ANSI color output is currently enabled.
// Exposed for other packages (e.g. cmd/topo) so they can short-circuit
// their own color paths consistently with RenderStatus/RenderScan etc.
func UseColor() bool {
	return useColor
}
