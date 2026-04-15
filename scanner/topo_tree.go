//go:build windows

package scanner

import (
	"path/filepath"
	"strings"
)

// TopoNode represents a directory in the space topology tree.
// Exported wrapper around the internal MFT node tree, which is the
// Tensorearch-derived topology graph (node-edge-weight propagation).
type TopoNode struct {
	Name     string
	Path     string
	Size     int64 // cumulative size (self + all descendants)
	IsDir    bool
	Children []*TopoNode
}

// ScanTopo performs a full MFT scan and returns the directory tree
// with cumulative sizes already propagated bottom-up by the MFT engine.
// Returns (nil, result, nil) if MFT is unavailable — caller should fall back.
func ScanTopo(path string, opts ScanOptions) (*TopoNode, *ScanResult, error) {
	if !isAdmin() || !isNTFS(path) {
		return nil, nil, nil
	}

	eng := &MFTEngine{}
	result, err := eng.Scan(path, opts)
	if err != nil {
		return nil, nil, err
	}

	// Build exported tree from the retained internal nodes
	root := buildTopoFromMFT(eng.nodes, eng.rootEntry, eng.basePath)
	return root, result, nil
}

// buildTopoFromMFT converts the internal mftNode map to an exported TopoNode tree.
func buildTopoFromMFT(nodes map[uint64]*mftNode, rootEntry uint64, basePath string) *TopoNode {
	rootNode, ok := nodes[rootEntry]
	if !ok {
		return nil
	}

	return convertNode(nodes, rootEntry, rootNode, basePath)
}

func convertNode(nodes map[uint64]*mftNode, entryNum uint64, node *mftNode, path string) *TopoNode {
	topo := &TopoNode{
		Name:  node.name,
		Path:  path,
		Size:  node.cumSize,
		IsDir: node.isDir,
	}

	for _, childNum := range node.children {
		child, ok := nodes[childNum]
		if !ok || !child.inUse {
			continue
		}
		if childNum <= 23 && strings.HasPrefix(child.name, "$") {
			continue
		}
		childPath := filepath.Join(path, child.name)
		childTopo := convertNode(nodes, childNum, child, childPath)
		topo.Children = append(topo.Children, childTopo)
	}

	return topo
}
