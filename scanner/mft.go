//go:build windows

package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"

	"github.com/shirou/gopsutil/v3/disk"
)

// MFTEngine reads NTFS Master File Table directly for ~3s/TB scan speed.
// Requires Administrator privileges.
// Uses Velocidex/go-ntfs for MFT record parsing.
type MFTEngine struct{}

func (e *MFTEngine) Name() string { return "mft" }

// mftNode tracks per-entry data during MFT traversal.
type mftNode struct {
	name      string
	parentRef uint64 // parent MFT entry number
	size      int64  // own file size (0 for directories)
	cumSize   int64  // cumulative size (self + descendants)
	isDir     bool
	lastMod   time.Time
	children  []uint64 // child entry numbers (populated in tree pass)
	inUse     bool
}

func (e *MFTEngine) Scan(path string, opts ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	if !isAdmin() {
		return nil, fmt.Errorf("MFT engine requires Administrator privileges; run as admin or use --engine fastwalk")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path %s: %w", path, err)
	}

	// Extract drive letter → open raw volume
	driveLetter := extractDriveLetter(absPath)
	if driveLetter == "" {
		return nil, fmt.Errorf("cannot determine drive letter from path %s", absPath)
	}

	volumePath := `\\.\` + driveLetter + ":"
	fh, err := openRawVolume(volumePath)
	if err != nil {
		return nil, fmt.Errorf("opening raw volume %s: %w (are you running as Administrator?)", volumePath, err)
	}
	defer fh.Close()

	// Wrap in sector-aligned reader — Windows raw volumes require
	// all reads to be multiples of 512 bytes (sector size).
	reader := &sectorAlignedReader{fh: fh, sectorSize: 512}

	// Get NTFS context
	ntfsCtx, err := ntfs.GetNTFSContext(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing NTFS boot sector on %s: %w", volumePath, err)
	}
	defer ntfsCtx.Close()

	// Bootstrap the MFT to get a reader over the full $MFT file
	mftReader, err := ntfs.BootstrapMFT(ntfsCtx)
	if err != nil {
		return nil, fmt.Errorf("bootstrapping MFT on %s: %w", volumePath, err)
	}

	// Determine MFT size heuristic: read from boot sector
	clusterSize := ntfsCtx.ClusterSize
	recordSize := ntfsCtx.RecordSize
	if recordSize <= 0 {
		recordSize = 1024
	}
	if clusterSize <= 0 {
		clusterSize = 4096
	}

	// Get total volume size for MFT size estimation
	usage, usageErr := disk.Usage(absPath)
	var totalBytes, freeBytes, usedBytes int64
	if usageErr == nil {
		totalBytes = int64(usage.Total)
		freeBytes = int64(usage.Free)
		usedBytes = int64(usage.Used)
	}

	// Estimate MFT size: typically ~12.5% of volume, but we use a generous upper bound
	// ParseMFTFile handles EOF gracefully
	mftSize := totalBytes
	if mftSize <= 0 {
		mftSize = 4 * 1024 * 1024 * 1024 * 1024 // 4TB fallback
	}

	// Parse all MFT records
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nodes := make(map[uint64]*mftNode)

	ch := ntfs.ParseMFTFile(ctx, mftReader, mftSize, clusterSize, recordSize)
	for record := range ch {
		if !record.InUse {
			continue
		}

		name := record.FileName()
		if name == "" || !utf8.ValidString(name) {
			continue
		}

		// Skip NTFS metafiles ($MFT, $MFTMirr, etc.) but keep . (root)
		if record.EntryNumber < 24 && record.EntryNumber != 5 {
			// Entry 5 is the root directory
			if strings.HasPrefix(name, "$") {
				continue
			}
		}

		node := &mftNode{
			name:      name,
			parentRef: record.ParentEntryNumber,
			size:      record.FileSize,
			isDir:     record.IsDir,
			lastMod:   record.LastModified0x10,
			inUse:     true,
		}
		if node.isDir {
			node.size = 0
		}
		node.cumSize = node.size

		nodes[uint64(record.EntryNumber)] = node
	}

	// Build parent→children links
	for entryNum, node := range nodes {
		if entryNum == 5 {
			continue // root has no meaningful parent
		}
		parent, ok := nodes[node.parentRef]
		if ok {
			parent.children = append(parent.children, entryNum)
		}
	}

	// Compute cumulative sizes bottom-up using iterative post-order traversal.
	// We process nodes in reverse topological order: leaves first, then parents.
	// Simple approach: iterate until stable (since MFT tree is a DAG from root).
	computeCumulativeSizes(nodes)

	// Determine which entries are "top-level" relative to the scan path.
	// If scanning a drive root (e.g. C:\), top-level = children of MFT entry 5.
	// If scanning a subdirectory, we need to find its MFT entry first.
	scanRoot := uint64(5) // NTFS root directory is always entry 5

	// Normalize absPath for comparison: "C:\" → just use root entry 5
	// For subdirectories, walk the tree to find the target entry
	relPath := strings.TrimPrefix(absPath, driveLetter+":\\")
	relPath = strings.TrimPrefix(relPath, driveLetter+":/")
	if relPath != "" && relPath != absPath {
		scanRoot = findEntryByPath(nodes, 5, relPath)
	}

	rootNode, rootExists := nodes[scanRoot]
	if !rootExists {
		return nil, fmt.Errorf("could not locate scan root directory in MFT for path %s", absPath)
	}

	// Build top-N from children of scanRoot
	topN := opts.TopN
	if topN <= 0 {
		topN = 20
	}
	heap := NewTopN(topN)

	for _, childNum := range rootNode.children {
		child, ok := nodes[childNum]
		if !ok || !child.inUse {
			continue
		}

		fullPath := filepath.Join(absPath, child.name)
		entry := DirEntry{
			Path:         fullPath,
			SizeBytes:    child.cumSize,
			IsDir:        child.isDir,
			ChildCount:   len(child.children),
			LastModified: child.lastMod,
		}
		heap.Add(entry)
	}

	// For CollectAll mode (hunt), also gather all directories
	var allDirs []DirEntry
	if opts.CollectAll {
		allDirs = collectAllDirs(nodes, scanRoot, absPath)
	}

	// Compute scan coverage: we see everything via MFT
	coverage := 1.0

	entries := heap.Sorted()
	if opts.CollectAll {
		entries = append(entries, allDirs...)
	}

	result := &ScanResult{
		RootPath:     absPath,
		TotalBytes:   totalBytes,
		FreeBytes:    freeBytes,
		UsedBytes:    usedBytes,
		Entries:      entries,
		DeniedPaths:  nil, // MFT bypasses ACLs
		ScanCoverage: coverage,
		DurationMs:   time.Since(startTime).Milliseconds(),
		EngineName:   e.Name(),
	}

	return result, nil
}

// computeCumulativeSizes propagates file sizes up the directory tree.
// Uses iterative approach: keep propagating until no changes occur.
func computeCumulativeSizes(nodes map[uint64]*mftNode) {
	// Build in-degree count for topological sort
	// Process leaves first, then work upward
	childCount := make(map[uint64]int, len(nodes))
	for entryNum := range nodes {
		childCount[entryNum] = 0
	}
	for entryNum, node := range nodes {
		if entryNum == 5 {
			continue
		}
		if _, ok := nodes[node.parentRef]; ok {
			childCount[node.parentRef]++
		}
	}

	// Queue: start with leaves (nodes with no children in our map)
	queue := make([]uint64, 0, len(nodes)/2)
	for entryNum := range nodes {
		if childCount[entryNum] == 0 {
			queue = append(queue, entryNum)
		}
	}

	for len(queue) > 0 {
		entryNum := queue[0]
		queue = queue[1:]

		node := nodes[entryNum]
		if entryNum == 5 {
			continue
		}

		parent, ok := nodes[node.parentRef]
		if !ok {
			continue
		}

		parent.cumSize += node.cumSize

		childCount[node.parentRef]--
		if childCount[node.parentRef] == 0 {
			queue = append(queue, node.parentRef)
		}
	}
}

// findEntryByPath walks the MFT tree to find the entry matching a relative path.
func findEntryByPath(nodes map[uint64]*mftNode, root uint64, relPath string) uint64 {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	current := root

	for _, part := range parts {
		if part == "" {
			continue
		}
		partLower := strings.ToLower(part)
		found := false

		node, ok := nodes[current]
		if !ok {
			return root // fallback
		}

		for _, childNum := range node.children {
			child, ok := nodes[childNum]
			if ok && strings.ToLower(child.name) == partLower {
				current = childNum
				found = true
				break
			}
		}

		if !found {
			return root // couldn't find path component, fallback to root
		}
	}

	return current
}

// collectAllDirs recursively collects all directory entries for hunt mode.
func collectAllDirs(nodes map[uint64]*mftNode, root uint64, basePath string) []DirEntry {
	var result []DirEntry

	rootNode, ok := nodes[root]
	if !ok {
		return result
	}

	type stackItem struct {
		entryNum uint64
		path     string
	}

	stack := make([]stackItem, 0, len(rootNode.children))
	for _, childNum := range rootNode.children {
		child, ok := nodes[childNum]
		if ok {
			stack = append(stack, stackItem{childNum, filepath.Join(basePath, child.name)})
		}
	}

	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		node, ok := nodes[item.entryNum]
		if !ok || !node.inUse {
			continue
		}

		if node.isDir {
			result = append(result, DirEntry{
				Path:         item.path,
				SizeBytes:    node.cumSize,
				IsDir:        true,
				ChildCount:   len(node.children),
				LastModified: node.lastMod,
			})

			for _, childNum := range node.children {
				child, ok := nodes[childNum]
				if ok {
					stack = append(stack, stackItem{childNum, filepath.Join(item.path, child.name)})
				}
			}
		} else if isVDiskExt(strings.ToLower(node.name)) {
			result = append(result, DirEntry{
				Path:         item.path,
				SizeBytes:    node.size,
				IsDir:        false,
				LastModified: node.lastMod,
			})
		}
	}

	return result
}

// sectorAlignedReader wraps an *os.File to ensure all ReadAt calls are
// aligned to sector boundaries. Windows raw volume I/O requires this.
type sectorAlignedReader struct {
	fh         *os.File
	sectorSize int64
}

func (r *sectorAlignedReader) ReadAt(p []byte, off int64) (int, error) {
	alignedOff := (off / r.sectorSize) * r.sectorSize
	delta := off - alignedOff
	readSize := ((int64(len(p)) + delta + r.sectorSize - 1) / r.sectorSize) * r.sectorSize

	buf := make([]byte, readSize)
	_, readErr := r.fh.ReadAt(buf, alignedOff)
	if readErr != nil && readErr != io.EOF {
		return 0, readErr
	}

	copied := copy(p, buf[delta:])
	if copied < len(p) {
		return copied, io.EOF
	}
	return copied, nil
}

// openRawVolume opens a Windows raw volume using CreateFile with proper flags.
func openRawVolume(volumePath string) (*os.File, error) {
	pathW, err := syscall.UTF16PtrFromString(volumePath)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		pathW,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), volumePath), nil
}
