//go:build !windows

package scanner

import (
	"fmt"
	"os"
)

// MFTEngine is not available on non-Windows platforms.
type MFTEngine struct{}

func (e *MFTEngine) Name() string { return "mft" }

func (e *MFTEngine) Scan(_ string, _ ScanOptions) (*ScanResult, error) {
	return nil, fmt.Errorf("MFT engine is only available on Windows")
}

// isAdmin on non-Windows checks for root (uid 0).
func isAdmin() bool {
	return os.Getuid() == 0
}

// isNTFS always returns false on non-Windows.
func isNTFS(_ string) bool {
	return false
}

// isReFS always returns false on non-Windows.
func isReFS(_ string) bool {
	return false
}
