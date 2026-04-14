//go:build windows

package scanner

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"

	"github.com/shirou/gopsutil/v3/disk"
)

// MFTEngine reads NTFS Master File Table directly for fast full-disk scan.
// Requires Administrator privileges.
type MFTEngine struct{}

func (e *MFTEngine) Name() string { return "mft" }

// mftNode tracks per-entry data during MFT traversal.
type mftNode struct {
	name      string
	parentRef uint64
	size      int64
	cumSize   int64
	isDir     bool
	lastMod   time.Time
	children  []uint64
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

	reader := &sectorAlignedReader{fh: fh, sectorSize: 512}

	// Use go-ntfs only for bootstrap (getting MFT location + reader)
	ntfsCtx, err := ntfs.GetNTFSContext(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing NTFS boot sector on %s: %w", volumePath, err)
	}

	clusterSize := ntfsCtx.ClusterSize
	recordSize := ntfsCtx.RecordSize
	if recordSize <= 0 {
		recordSize = 1024
	}
	if clusterSize <= 0 {
		clusterSize = 4096
	}

	mftReader, err := ntfs.BootstrapMFT(ntfsCtx)
	ntfsCtx.Close() // Done with go-ntfs, close early

	if err != nil {
		return nil, fmt.Errorf("bootstrapping MFT on %s: %w", volumePath, err)
	}

	// Get volume info
	usage, usageErr := disk.Usage(absPath)
	var totalBytes, freeBytes, usedBytes int64
	if usageErr == nil {
		totalBytes = int64(usage.Total)
		freeBytes = int64(usage.Free)
		usedBytes = int64(usage.Used)
	}

	// Estimate MFT entry count from volume size
	// Typical: ~1 MFT record per 4KB of disk, but cap at reasonable max
	estEntries := totalBytes / recordSize
	if estEntries > 20_000_000 {
		estEntries = 20_000_000 // cap at 20M entries
	}

	// Phase 1: Read and parse MFT records in parallel
	nodes := make(map[uint64]*mftNode, estEntries/2)
	var nodesMu sync.Mutex

	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 2 {
		numWorkers = 2
	}

	type rawRecord struct {
		id   int64
		data []byte
	}

	recordCh := make(chan rawRecord, numWorkers*4)
	var wg sync.WaitGroup
	t1 := time.Now()

	// Producer: batch-read MFT records using OPU-style prefetch coalescing.
	// Instead of 1KB per ReadAt (1000+ I/O ops per second), read 1MB chunks
	// (1024 records) and slice in memory. Reduces I/O syscalls by ~1000x.
	const batchSize = 1024 // records per I/O batch
	go func() {
		defer close(recordCh)
		batchBuf := make([]byte, recordSize*batchSize)
		var parsed int64
		for batchStart := int64(0); ; batchStart += batchSize {
			// One large I/O: read 1MB at once
			n, err := mftReader.ReadAt(batchBuf, batchStart*recordSize)
			if n == 0 {
				break
			}
			// Process records within this batch
			recordsInBatch := int64(n) / recordSize
			for i := int64(0); i < recordsInBatch; i++ {
				offset := i * recordSize
				rec := batchBuf[offset : offset+recordSize]
				// Quick check: "FILE" magic
				if string(rec[0:4]) != "FILE" {
					continue
				}
				// Copy for goroutine safety
				record := make([]byte, recordSize)
				copy(record, rec)
				recordCh <- rawRecord{id: batchStart + i, data: record}
				parsed++
			}
			if parsed%100000 < batchSize {
				fmt.Fprintf(os.Stderr, "\r  MFT: %dk records read...", parsed/1000)
			}
			if err == io.EOF {
				break
			}
		}
		fmt.Fprintf(os.Stderr, "\r  MFT: %dk records read, building tree...\n", parsed/1000)
	}()

	// Track entries that need external $DATA resolution
	type pendingRef struct {
		ownerID    uint64 // the MFT entry that owns the file
		externalID uint64 // the MFT entry that holds the $DATA
	}
	var pendingRefs []pendingRef
	var pendingMu sync.Mutex

	// Workers: parse MFT records in parallel (CPU bound)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localNodes := make(map[uint64]*mftNode, 1000)
			var localPending []pendingRef

			for rec := range recordCh {
				node, extRefs := parseMFTRecord(rec.data, recordSize, opts)
				if node != nil {
					localNodes[uint64(rec.id)] = node
					// If file has no size but has external $DATA references, queue for second pass
					if node.size == 0 && !node.isDir && len(extRefs) > 0 {
						for _, ref := range extRefs {
							if ref != uint64(rec.id) { // skip self-references
								localPending = append(localPending, pendingRef{
									ownerID:    uint64(rec.id),
									externalID: ref,
								})
							}
						}
					}
				}
			}

			// Merge into global map
			nodesMu.Lock()
			for k, v := range localNodes {
				nodes[k] = v
			}
			nodesMu.Unlock()

			pendingMu.Lock()
			pendingRefs = append(pendingRefs, localPending...)
			pendingMu.Unlock()
		}()
	}

	wg.Wait()
	fmt.Fprintf(os.Stderr, "  Phase 1 (read+parse): %v, %d nodes\n", time.Since(t1), len(nodes))

	// Phase 1.5: Resolve external $DATA references using ring buffer.
	// Sort pending refs by external entry number so we read MFT sequentially,
	// then batch nearby records into single I/O operations.
	if len(pendingRefs) > 0 {
		fmt.Fprintf(os.Stderr, "  Resolving %d external refs (ring buffer)...\n", len(pendingRefs))

		// First: resolve from already-parsed nodes (no I/O needed)
		var needIO []pendingRef
		resolved := 0
		for _, ref := range pendingRefs {
			owner, ok := nodes[ref.ownerID]
			if !ok || owner.size > 0 {
				continue
			}
			if ext, ok := nodes[ref.externalID]; ok && ext.size > 0 {
				owner.size = ext.size
				owner.cumSize = ext.size
				resolved++
			} else {
				needIO = append(needIO, ref)
			}
		}

		// Sort remaining by external entry number for sequential I/O
		sort.Slice(needIO, func(i, j int) bool {
			return needIO[i].externalID < needIO[j].externalID
		})

		// Ring buffer: read a window of MFT records at once, resolve all refs within that window
		const ringSize = 2048 // records per ring read (2MB)
		ringBuf := make([]byte, recordSize*ringSize)
		ringStart := int64(-1) // first entry number in current ring

		for _, ref := range needIO {
			owner, ok := nodes[ref.ownerID]
			if !ok || owner.size > 0 {
				continue
			}
			extID := int64(ref.externalID)

			// Check if the entry is within the current ring buffer
			if ringStart < 0 || extID < ringStart || extID >= ringStart+ringSize {
				// Load new ring centered on this entry
				ringStart = extID - extID%ringSize // align to ring boundary
				mftReader.ReadAt(ringBuf, ringStart*recordSize)
			}

			// Extract from ring buffer
			ringOffset := (extID - ringStart) * recordSize
			if ringOffset < 0 || ringOffset+recordSize > int64(len(ringBuf)) {
				continue
			}
			rec := ringBuf[ringOffset : ringOffset+recordSize]
			if string(rec[0:4]) != "FILE" {
				continue
			}
			// Apply fixup on a copy (don't corrupt ring buffer)
			recCopy := make([]byte, recordSize)
			copy(recCopy, rec)
			applyFixup(recCopy)

			extSize := extractDataSize(recCopy, recordSize)
			if extSize > 0 {
				owner.size = extSize
				owner.cumSize = extSize
				resolved++
			}
		}
		// Möbius twist: only for the specific unresolved pendingRefs owners.
		// Don't scan all 31K+ zero-size files — most are genuinely empty.
		unresolvedOwners := make(map[uint64]bool)
		for _, ref := range needIO {
			owner, ok := nodes[ref.ownerID]
			if ok && owner.size == 0 {
				unresolvedOwners[ref.ownerID] = true
			}
		}
		if len(unresolvedOwners) > 0 {
			fmt.Fprintf(os.Stderr, "  Möbius pass: %d unresolved owners...\n", len(unresolvedOwners))
			mobiusResolved := 0
			for entryNum := range unresolvedOwners {
				node, ok := nodes[entryNum]
				if !ok || node.size > 0 {
					continue
				}
				// Re-read the owner record
				ownerBuf := make([]byte, recordSize)
				n, err := mftReader.ReadAt(ownerBuf, int64(entryNum)*recordSize)
				if err != nil || n < int(recordSize) || string(ownerBuf[0:4]) != "FILE" {
					continue
				}
				applyFixup(ownerBuf)

				// Walk attributes looking for non-resident $ATTRIBUTE_LIST (type 0x20)
				ao := int(binary.LittleEndian.Uint16(ownerBuf[0x14:0x16]))
				for ao+8 < int(recordSize) && ao+8 < len(ownerBuf) {
					at := binary.LittleEndian.Uint32(ownerBuf[ao : ao+4])
					if at == 0xFFFFFFFF {
						break
					}
					al := int(binary.LittleEndian.Uint32(ownerBuf[ao+4 : ao+8]))
					if al <= 0 || ao+al > len(ownerBuf) {
						break
					}
					if at == 0x20 && ownerBuf[ao+8] != 0 {
						// Non-resident $ATTRIBUTE_LIST found!
						// Read the real size and data runs offset
						if ao+0x40 <= len(ownerBuf) {
							alRealSize := int64(binary.LittleEndian.Uint64(ownerBuf[ao+0x38 : ao+0x40]))
							drOffset := int(binary.LittleEndian.Uint16(ownerBuf[ao+0x20 : ao+0x22]))
							if alRealSize > 0 && alRealSize < 65536 && drOffset > 0 {
								// Decode data runs and read the attribute list content
								alContent := readDataRuns(ownerBuf[ao+drOffset:ao+al], mftReader, clusterSize, alRealSize)
								if alContent != nil {
									refs := parseAttributeList(alContent, 0x80)
									for _, ref := range refs {
										if ref == uint64(entryNum) {
											continue
										}
										// Read external record via ring
										extBuf := make([]byte, recordSize)
										en, eerr := mftReader.ReadAt(extBuf, int64(ref)*recordSize)
										if eerr != nil || en < int(recordSize) || string(extBuf[0:4]) != "FILE" {
											continue
										}
										applyFixup(extBuf)
										extSize := extractDataSize(extBuf, recordSize)
										if extSize > 0 {
											node.size = extSize
											node.cumSize = extSize
											mobiusResolved++
											break
										}
									}
								}
							}
						}
					}
					ao += al
				}
			}
			resolved += mobiusResolved
			fmt.Fprintf(os.Stderr, "  Möbius resolved: %d additional\n", mobiusResolved)
		}

		fmt.Fprintf(os.Stderr, "  Total resolved: %d / %d external references\n", resolved, len(pendingRefs))
	}

	// Phase 2: Build parent-child links
	t2 := time.Now()
	for entryNum, node := range nodes {
		if parent, ok := nodes[node.parentRef]; ok && entryNum != 5 {
			parent.children = append(parent.children, entryNum)
		}
	}
	fmt.Fprintf(os.Stderr, "  Phase 2 (tree links): %v, %d nodes\n", time.Since(t2), len(nodes))

	// Phase 3: Compute cumulative sizes (bottom-up)
	t3 := time.Now()
	computeCumulativeSizes(nodes)
	fmt.Fprintf(os.Stderr, "  Phase 3 (cumulative sizes): %v\n", time.Since(t3))

	// Phase 4: Build results
	rootEntry := uint64(5) // NTFS root directory
	basePath := driveLetter + `:\`

	// If scanning a subdirectory, find its MFT entry
	relPath, _ := filepath.Rel(basePath, absPath)
	if relPath != "." && relPath != "" {
		rootEntry = findEntryByPath(nodes, 5, relPath)
		basePath = absPath
	}

	rootNode, ok := nodes[rootEntry]
	if !ok {
		return nil, fmt.Errorf("root entry not found in MFT")
	}

	topN := opts.TopN
	if topN <= 0 {
		topN = 20
	}
	h := NewTopN(topN)

	for _, childNum := range rootNode.children {
		child, ok := nodes[childNum]
		if !ok || !child.inUse {
			continue
		}
		// Skip NTFS metafiles from output (but they remain in tree for size propagation)
		if childNum <= 23 && strings.HasPrefix(child.name, "$") {
			continue
		}
		h.Add(DirEntry{
			Path:         filepath.Join(basePath, child.name),
			SizeBytes:    child.cumSize,
			IsDir:        child.isDir,
			ChildCount:   len(child.children),
			LastModified: child.lastMod,
		})
	}

	entries := h.Sorted()

	// CollectAll: add all directories for hunt mode
	if opts.CollectAll {
		allDirs := collectAllDirs(nodes, rootEntry, basePath)
		entries = append(entries, allDirs...)
	}

	return &ScanResult{
		RootPath:     absPath,
		TotalBytes:   totalBytes,
		FreeBytes:    freeBytes,
		UsedBytes:    usedBytes,
		Entries:      entries,
		ScanCoverage: 1.0,
		DurationMs:   time.Since(startTime).Milliseconds(),
		EngineName:   e.Name(),
	}, nil
}

// applyFixup applies the NTFS update sequence array fixup to a raw MFT record.
// NTFS replaces the last 2 bytes of each 512-byte sector with an update sequence
// number for integrity checking. The original values are stored in the fixup array
// at the beginning of the record. We must restore them before parsing attributes.
func applyFixup(data []byte) {
	if len(data) < 48 {
		return
	}
	usOffset := binary.LittleEndian.Uint16(data[0x04:0x06]) // update sequence offset
	usCount := binary.LittleEndian.Uint16(data[0x06:0x08])  // number of entries (1 check + N sector values)

	if usCount < 2 || int(usOffset)+int(usCount)*2 > len(data) {
		return
	}

	// First entry is the expected value at each sector end (for verification)
	// Subsequent entries are the original values to restore
	for i := uint16(1); i < usCount; i++ {
		// Position in the fixup array
		fixupPos := int(usOffset) + int(i)*2
		// Position in the record (last 2 bytes of each 512-byte sector)
		sectorEnd := int(i)*512 - 2

		if fixupPos+2 > len(data) || sectorEnd+2 > len(data) || sectorEnd < 0 {
			break
		}

		// Restore original bytes
		data[sectorEnd] = data[fixupPos]
		data[sectorEnd+1] = data[fixupPos+1]
	}
}

// parseMFTRecord extracts filename, size, parent FRN, and directory flag
// directly from a raw 1KB MFT record without go-ntfs attribute parsing.
// Also returns external MFT entry numbers from $ATTRIBUTE_LIST that hold
// $DATA attributes (needed for large/fragmented files).
func parseMFTRecord(data []byte, recordSize int64, opts ScanOptions) (*mftNode, []uint64) {
	if len(data) < 48 {
		return nil, nil
	}

	// Apply NTFS fixup before parsing any attributes
	applyFixup(data)

	// Check flags
	flags := binary.LittleEndian.Uint16(data[0x16:0x18])
	if flags&0x01 == 0 {
		return nil, nil // not in use
	}

	attrOffset := binary.LittleEndian.Uint16(data[0x14:0x16])
	isDir := flags&0x02 != 0

	var name string
	var parentRef uint64
	var fileSize int64
	var lastMod time.Time
	var externalDataRefs []uint64
	foundName := false

	// Walk attributes
	offset := int(attrOffset)
	for offset+4 < int(recordSize) && offset+4 < len(data) {
		attrType := binary.LittleEndian.Uint32(data[offset : offset+4])
		if attrType == 0xFFFFFFFF {
			break // end marker
		}

		attrLen := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if attrLen <= 0 || offset+attrLen > int(recordSize) || offset+attrLen > len(data) {
			break
		}

		switch attrType {
		case 0x20: // $ATTRIBUTE_LIST
			// Möbius side A: resident ATTRLIST — parse directly
			if alData := getResidentData(data, offset); alData != nil {
				externalDataRefs = append(externalDataRefs, parseAttributeList(alData, 0x80)...)
			}
			// Side B (non-resident ATTRLIST) is handled in the Möbius ring pass

		case 0x30: // $FILE_NAME
			if fnData := getResidentData(data, offset); fnData != nil && len(fnData) >= 66 {
				parentRef = binary.LittleEndian.Uint64(fnData[0:8]) & 0x0000FFFFFFFFFFFF

				nameLen := int(fnData[64])
				nameType := fnData[65]
				if nameLen > 0 && 66+nameLen*2 <= len(fnData) {
					utf16Chars := make([]uint16, nameLen)
					for i := 0; i < nameLen; i++ {
						utf16Chars[i] = binary.LittleEndian.Uint16(fnData[66+i*2 : 66+i*2+2])
					}
					decoded := string(utf16.Decode(utf16Chars))

					if !foundName || nameType == 1 || nameType == 3 {
						name = decoded
						foundName = true
					}
				}

				if len(fnData) >= 32 {
					ft := binary.LittleEndian.Uint64(fnData[24:32])
					lastMod = filetimeToTime(ft)
				}
			}

		case 0x80: // $DATA
			if fileSize == 0 {
				nonResident := data[offset+8]
				if nonResident == 0 {
					if offset+20 <= len(data) {
						fileSize = int64(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
					}
				} else {
					if offset+64 <= len(data) {
						fileSize = int64(binary.LittleEndian.Uint64(data[offset+56 : offset+64]))
					}
				}
			}
		}

		offset += attrLen
	}

	if name == "" {
		return nil, nil
	}

	// Apply time filter at parse level
	if !opts.AfterTime.IsZero() && !isDir && lastMod.Before(opts.AfterTime) {
		fileSize = 0
	}
	if !opts.BeforeTime.IsZero() && !isDir && lastMod.After(opts.BeforeTime) {
		fileSize = 0
	}

	return &mftNode{
		name:      name,
		parentRef: parentRef,
		size:      fileSize,
		cumSize:   fileSize,
		isDir:     isDir,
		lastMod:   lastMod,
		inUse:     true,
	}, externalDataRefs
}

// parseAttributeList parses a resident $ATTRIBUTE_LIST and returns MFT entry
// numbers of external records that hold the specified attribute type.
// $ATTRIBUTE_LIST entry format:
//
//	offset 0x00: attribute type (4)
//	offset 0x04: record length (2)
//	offset 0x06: name length (1)
//	offset 0x07: name offset (1)
//	offset 0x08: start VCN (8)
//	offset 0x10: MFT reference (8) — lower 48 bits = entry number
//	offset 0x18: attribute ID (2)
func parseAttributeList(data []byte, targetType uint32) []uint64 {
	var refs []uint64
	offset := 0
	for offset+0x1A <= len(data) {
		attrType := binary.LittleEndian.Uint32(data[offset : offset+4])
		entryLen := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
		if entryLen <= 0 || offset+entryLen > len(data) {
			break
		}
		if attrType == targetType {
			mftRef := binary.LittleEndian.Uint64(data[offset+0x10:offset+0x18]) & 0x0000FFFFFFFFFFFF
			refs = append(refs, mftRef)
		}
		offset += entryLen
	}
	return refs
}

// readDataRuns decodes NTFS data runs and reads the content they point to.
// Data runs encode (length, offset) pairs in a compact variable-length format.
// Used to read non-resident $ATTRIBUTE_LIST content from disk.
func readDataRuns(runData []byte, reader io.ReaderAt, clusterSize int64, realSize int64) []byte {
	result := make([]byte, 0, realSize)
	pos := 0
	prevLCN := int64(0)

	for pos < len(runData) {
		header := runData[pos]
		if header == 0 {
			break
		}
		lengthBytes := int(header & 0x0F)
		offsetBytes := int((header >> 4) & 0x0F)
		pos++

		if lengthBytes == 0 || pos+lengthBytes+offsetBytes > len(runData) {
			break
		}

		// Read run length (unsigned)
		runLength := int64(0)
		for i := lengthBytes - 1; i >= 0; i-- {
			runLength = (runLength << 8) | int64(runData[pos+i])
		}
		pos += lengthBytes

		// Read run offset (signed, relative to previous)
		runOffset := int64(0)
		if offsetBytes > 0 {
			for i := offsetBytes - 1; i >= 0; i-- {
				runOffset = (runOffset << 8) | int64(runData[pos+i])
			}
			// Sign extend
			if runData[pos+offsetBytes-1]&0x80 != 0 {
				for i := offsetBytes; i < 8; i++ {
					runOffset |= int64(0xFF) << uint(i*8)
				}
			}
			pos += offsetBytes
		} else {
			// Sparse run — skip
			continue
		}

		lcn := prevLCN + runOffset
		prevLCN = lcn

		// Read clusters
		readSize := runLength * clusterSize
		if int64(len(result))+readSize > realSize {
			readSize = realSize - int64(len(result))
		}
		buf := make([]byte, readSize)
		n, _ := reader.ReadAt(buf, lcn*clusterSize)
		result = append(result, buf[:n]...)

		if int64(len(result)) >= realSize {
			break
		}
	}

	if int64(len(result)) > realSize {
		result = result[:realSize]
	}
	return result
}

// extractDataSize reads only the $DATA attribute size from a raw MFT record.
// Used for resolving external attribute references.
func extractDataSize(data []byte, recordSize int64) int64 {
	if len(data) < 48 {
		return 0
	}
	attrOffset := int(binary.LittleEndian.Uint16(data[0x14:0x16]))
	offset := attrOffset
	for offset+8 < int(recordSize) && offset+8 < len(data) {
		attrType := binary.LittleEndian.Uint32(data[offset : offset+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		if attrLen <= 0 || offset+attrLen > len(data) {
			break
		}
		if attrType == 0x80 { // $DATA
			nonResident := data[offset+8]
			if nonResident == 0 {
				if offset+20 <= len(data) {
					return int64(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))
				}
			} else {
				if offset+64 <= len(data) {
					return int64(binary.LittleEndian.Uint64(data[offset+56 : offset+64]))
				}
			}
		}
		offset += attrLen
	}
	return 0
}

// getResidentData extracts the data of a resident attribute.
func getResidentData(data []byte, attrOffset int) []byte {
	if attrOffset+22 > len(data) {
		return nil
	}
	nonResident := data[attrOffset+8]
	if nonResident != 0 {
		return nil // non-resident, skip
	}
	dataLen := int(binary.LittleEndian.Uint32(data[attrOffset+16 : attrOffset+20]))
	dataOffset := int(binary.LittleEndian.Uint16(data[attrOffset+20 : attrOffset+22]))
	start := attrOffset + dataOffset
	if start+dataLen > len(data) || dataLen <= 0 {
		return nil
	}
	return data[start : start+dataLen]
}

// filetimeToTime converts Windows FILETIME (100-ns intervals since 1601-01-01) to Go time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// Windows FILETIME epoch: 1601-01-01
	// Unix epoch: 1970-01-01
	// Difference: 11644473600 seconds
	const epochDiff = 11644473600
	secs := int64(ft/10000000) - epochDiff
	nsec := int64(ft%10000000) * 100
	if secs < 0 {
		return time.Time{}
	}
	return time.Unix(secs, nsec)
}

// computeCumulativeSizes propagates file sizes up the directory tree.
func computeCumulativeSizes(nodes map[uint64]*mftNode) {
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

// findEntryByPath walks the MFT tree to find the entry for a relative path.
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
			return root
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
			return root
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
