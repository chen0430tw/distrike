package output

import (
	"os"
	"strconv"

	"golang.org/x/term"
)

// TermWidth returns the current terminal column width.
// Priority: COLUMNS env → term.GetSize(stdout) → term.GetSize(stderr) → 80.
func TermWidth() int {
	if c := envColumns(); c > 0 {
		return c
	}
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 20 {
		return w
	}
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 20 {
		return w
	}
	return 80
}

// UseUnicode reports whether Unicode box-drawing characters should be used.
func UseUnicode() bool {
	if v := os.Getenv("NO_UNICODE"); v != "" {
		return false
	}
	return true
}

func envColumns() int {
	v := os.Getenv("COLUMNS")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 20 {
		return 0
	}
	return n
}
