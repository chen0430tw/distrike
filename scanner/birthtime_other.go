//go:build !windows

package scanner

import (
	"os"
	"time"
)

// getBirthtime returns the file birthtime. On Linux, true birthtime requires
// statx(2) which is not exposed by os.FileInfo — return zero so callers treat
// it as "unknown" and skip creation-time filtering gracefully.
func getBirthtime(info os.FileInfo) time.Time {
	return time.Time{}
}
