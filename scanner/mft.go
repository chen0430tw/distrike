//go:build windows

package scanner

// MFTEngine reads NTFS Master File Table directly for ~3s/TB scan speed.
// Requires Administrator privileges.
// Uses Velocidex/go-ntfs for MFT record parsing.
type MFTEngine struct{}

func (e *MFTEngine) Name() string { return "mft" }

func (e *MFTEngine) Scan(path string, opts ScanOptions) (*ScanResult, error) {
	// TODO: Phase 4
	// 1. Open raw volume handle (\\.\C:)
	// 2. Read boot sector → locate $MFT offset
	// 3. Sequential read all MFT records (1KB each)
	// 4. Parse $FILE_NAME + $DATA attributes
	// 5. Reconstruct directory tree from Parent FRN
	// 6. Compute cumulative sizes
	// 7. Return ScanResult
	return nil, nil
}
