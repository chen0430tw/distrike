//go:build !windows

package scanner

// TopoNode represents a directory in the space topology tree.
type TopoNode struct {
	Name     string
	Path     string
	Size     int64
	IsDir    bool
	Children []*TopoNode
}

// ScanTopo is not available on non-Windows (no MFT engine).
// Returns nil — caller should fall back to fastwalk-based topo.
func ScanTopo(path string, opts ScanOptions) (*TopoNode, *ScanResult, error) {
	return nil, nil, nil
}
