//go:build windows

package scanner

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	ntfs "www.velocidex.com/golang/go-ntfs/parser"

	"github.com/shirou/gopsutil/v3/disk"
)

// Bitset is a direct-indexed bit array keyed by MFT entry number.
// No hashing needed — entry numbers are sequential integers.
// 2M entries = 256KB memory.
type Bitset struct {
	bits []uint64
	size uint64
}

func NewBitset(maxEntry uint64) *Bitset {
	words := (maxEntry + 63) / 64
	return &Bitset{bits: make([]uint64, words), size: maxEntry}
}

func (b *Bitset) Set(n uint64) {
	if n < b.size {
		b.bits[n/64] |= 1 << (n % 64)
	}
}

func (b *Bitset) Test(n uint64) bool {
	if n >= b.size {
		return false
	}
	return b.bits[n/64]&(1<<(n%64)) != 0
}

func (b *Bitset) Clear(n uint64) {
	if n < b.size {
		b.bits[n/64] &^= 1 << (n % 64)
	}
}

// Count returns the number of set bits (popcount).
func (b *Bitset) Count() uint64 {
	var count uint64
	for _, w := range b.bits {
		// Hamming weight / popcount
		w = w - ((w >> 1) & 0x5555555555555555)
		w = (w & 0x3333333333333333) + ((w >> 2) & 0x3333333333333333)
		count += (((w + (w >> 4)) & 0x0F0F0F0F0F0F0F0F) * 0x0101010101010101) >> 56
	}
	return count
}

// USN Journal structures
type USN_JOURNAL_DATA struct {
	UsnJournalID    uint64
	FirstUsn        int64
	NextUsn         int64
	LowestValidUsn  int64
	MaxUsn          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type USN_RECORD_V2 struct {
	RecordLength              uint32
	MajorVersion              uint16
	MinorVersion              uint16
	FileReferenceNumber       uint64
	ParentFileReferenceNumber uint64
	Usn                       int64
	TimeStamp                 int64
	Reason                    uint32
	SourceInfo                uint32
	SecurityId                uint32
	FileAttributes            uint32
	FileNameLength            uint16
	FileNameOffset            uint16
	// FileName follows at FileNameOffset (UTF-16LE)
}

const (
	FSCTL_QUERY_USN_JOURNAL = 0x000900F4
	FSCTL_READ_USN_JOURNAL  = 0x000900BB
	FSCTL_ENUM_USN_DATA     = 0x000900B3

	USN_REASON_DATA_OVERWRITE  = 0x00000001
	USN_REASON_DATA_EXTEND     = 0x00000002
	USN_REASON_DATA_TRUNCATION = 0x00000004
	USN_REASON_FILE_CREATE     = 0x00000100
	USN_REASON_FILE_DELETE      = 0x00000200
	USN_REASON_RENAME_NEW_NAME  = 0x00002000
	USN_REASON_CLOSE            = 0x80000000
)

// USNScanner implements incremental scanning via NTFS USN Journal.
// First scan: full MFT walk + save USN cursor.
// Subsequent scans: read USN changes since cursor → update only changed entries.
type USNScanner struct {
	volumePath string
	volumeH    syscall.Handle
}

// USNDelta represents changes detected since last scan.
type USNDelta struct {
	Created  []uint64 // new file entry numbers
	Modified []uint64 // modified file entry numbers
	Deleted  []uint64 // deleted file entry numbers
	NextUsn  int64    // cursor for next incremental scan
}

// OpenUSN opens a volume for USN Journal access.
func OpenUSN(driveLetter string) (*USNScanner, error) {
	volumePath := `\\.\` + strings.ToUpper(driveLetter) + ":"
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
		return nil, fmt.Errorf("opening volume %s: %w", volumePath, err)
	}
	return &USNScanner{volumePath: volumePath, volumeH: h}, nil
}

func (u *USNScanner) Close() {
	syscall.CloseHandle(u.volumeH)
}

// QueryJournal returns the current USN Journal state.
func (u *USNScanner) QueryJournal() (*USN_JOURNAL_DATA, error) {
	var data USN_JOURNAL_DATA
	var bytesReturned uint32
	err := syscall.DeviceIoControl(
		u.volumeH,
		FSCTL_QUERY_USN_JOURNAL,
		nil, 0,
		(*byte)(unsafe.Pointer(&data)), uint32(unsafe.Sizeof(data)),
		&bytesReturned, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("FSCTL_QUERY_USN_JOURNAL: %w", err)
	}
	return &data, nil
}

// ReadChanges reads USN Journal entries since the given cursor.
// Uses full-permutation optimized batch read: reads the maximum buffer
// and sorts changes by entry number for sequential cache access.
func (u *USNScanner) ReadChanges(fromUsn int64, journalID uint64) (*USNDelta, error) {
	delta := &USNDelta{}

	// Full-permutation optimization: use large buffer to batch all changes
	// in one syscall, then sort by entry number for sequential processing.
	type readInput struct {
		StartUsn          int64
		ReasonMask        uint32
		ReturnOnlyOnClose uint32
		Timeout           uint64
		BytesToWaitFor    uint64
		UsnJournalID      uint64
	}

	input := readInput{
		StartUsn: fromUsn,
		ReasonMask: USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
			USN_REASON_DATA_TRUNCATION | USN_REASON_FILE_CREATE |
			USN_REASON_FILE_DELETE | USN_REASON_RENAME_NEW_NAME |
			USN_REASON_CLOSE,
		UsnJournalID: journalID,
	}

	// 64KB buffer — captures thousands of USN records per syscall
	buf := make([]byte, 65536)
	var bytesReturned uint32

	for {
		err := syscall.DeviceIoControl(
			u.volumeH,
			FSCTL_READ_USN_JOURNAL,
			(*byte)(unsafe.Pointer(&input)), uint32(unsafe.Sizeof(input)),
			&buf[0], uint32(len(buf)),
			&bytesReturned, nil,
		)
		if err != nil {
			// ERROR_HANDLE_EOF or similar — no more data
			break
		}
		if bytesReturned <= 8 {
			break // only the next USN, no records
		}

		// First 8 bytes: next USN value
		nextUsn := int64(binary.LittleEndian.Uint64(buf[0:8]))
		delta.NextUsn = nextUsn

		// Parse USN records
		offset := uint32(8)
		for offset < bytesReturned {
			if offset+4 > bytesReturned {
				break
			}
			recLen := binary.LittleEndian.Uint32(buf[offset : offset+4])
			if recLen == 0 || offset+recLen > bytesReturned {
				break
			}

			if recLen >= uint32(unsafe.Sizeof(USN_RECORD_V2{})) {
				rec := (*USN_RECORD_V2)(unsafe.Pointer(&buf[offset]))
				entryNum := rec.FileReferenceNumber & 0x0000FFFFFFFFFFFF
				reason := rec.Reason

				if reason&USN_REASON_FILE_DELETE != 0 {
					delta.Deleted = append(delta.Deleted, entryNum)
				} else if reason&USN_REASON_FILE_CREATE != 0 {
					delta.Created = append(delta.Created, entryNum)
				} else if reason&(USN_REASON_DATA_OVERWRITE|USN_REASON_DATA_EXTEND|USN_REASON_DATA_TRUNCATION) != 0 {
					delta.Modified = append(delta.Modified, entryNum)
				}
			}

			offset += recLen
		}

		// Advance cursor
		input.StartUsn = delta.NextUsn
	}

	return delta, nil
}

// IncrementalScan performs a fast incremental scan using USN Journal.
// Requires a previous full MFT scan's node map and USN cursor.
func IncrementalScan(
	driveLetter string,
	prevNodes map[uint64]*mftNode,
	prevUsn int64,
	opts ScanOptions,
) (*ScanResult, error) {
	startTime := time.Now()

	usn, err := OpenUSN(driveLetter)
	if err != nil {
		return nil, fmt.Errorf("opening USN: %w", err)
	}
	defer usn.Close()

	journal, err := usn.QueryJournal()
	if err != nil {
		return nil, fmt.Errorf("querying USN journal: %w", err)
	}

	// Read changes since last scan
	delta, err := usn.ReadChanges(prevUsn, journal.UsnJournalID)
	if err != nil {
		return nil, fmt.Errorf("reading USN changes: %w", err)
	}

	totalChanges := len(delta.Created) + len(delta.Modified) + len(delta.Deleted)
	fmt.Fprintf(os.Stderr, "  USN: %d changes (%d new, %d modified, %d deleted)\n",
		totalChanges, len(delta.Created), len(delta.Modified), len(delta.Deleted))

	if totalChanges == 0 {
		fmt.Fprintf(os.Stderr, "  No changes since last scan\n")
	}

	// Build bitset of changed entries for O(1) lookup
	maxEntry := uint64(0)
	for _, e := range delta.Created {
		if e > maxEntry {
			maxEntry = e
		}
	}
	for _, e := range delta.Modified {
		if e > maxEntry {
			maxEntry = e
		}
	}
	for k := range prevNodes {
		if k > maxEntry {
			maxEntry = k
		}
	}

	changedSet := NewBitset(maxEntry + 1)
	for _, e := range delta.Created {
		changedSet.Set(e)
	}
	for _, e := range delta.Modified {
		changedSet.Set(e)
	}

	// Apply deletes
	for _, e := range delta.Deleted {
		delete(prevNodes, e)
	}

	// For created/modified entries, we need to re-read their MFT records
	// to get updated size. Use the MFT reader with ring buffer for batch access.
	if len(delta.Created)+len(delta.Modified) > 0 {
		fh, err := openRawVolume(`\\.\` + strings.ToUpper(driveLetter) + ":")
		if err != nil {
			return nil, fmt.Errorf("opening volume for MFT re-read: %w", err)
		}
		defer fh.Close()

		reader := &sectorAlignedReader{fh: fh, sectorSize: 512}
		ntfsCtx, err := ntfsBootstrapOnly(reader)
		if err != nil {
			return nil, err
		}

		recordSize := ntfsCtx.recordSize
		mftReader := ntfsCtx.mftReader

		// Full-permutation: sort changed entries for sequential MFT access
		allChanged := make([]uint64, 0, len(delta.Created)+len(delta.Modified))
		allChanged = append(allChanged, delta.Created...)
		allChanged = append(allChanged, delta.Modified...)
		sortUint64(allChanged)

		// Ring buffer re-read
		const ringSize = 2048
		ringBuf := make([]byte, recordSize*ringSize)
		ringStart := int64(-1)

		for _, entryNum := range allChanged {
			extID := int64(entryNum)
			if ringStart < 0 || extID < ringStart || extID >= ringStart+ringSize {
				ringStart = extID - extID%ringSize
				mftReader.ReadAt(ringBuf, ringStart*recordSize)
			}

			ringOffset := (extID - ringStart) * recordSize
			if ringOffset < 0 || ringOffset+recordSize > int64(len(ringBuf)) {
				continue
			}
			rec := ringBuf[ringOffset : ringOffset+recordSize]
			if string(rec[0:4]) != "FILE" {
				continue
			}
			recCopy := make([]byte, recordSize)
			copy(recCopy, rec)
			node, _ := parseMFTRecord(recCopy, recordSize, opts)
			if node != nil {
				prevNodes[entryNum] = node
			}
		}
	}

	// Rebuild tree and cumulative sizes
	// Clear old children links
	for _, node := range prevNodes {
		node.children = nil
		node.cumSize = node.size
	}
	for entryNum, node := range prevNodes {
		if parent, ok := prevNodes[node.parentRef]; ok && entryNum != 5 {
			parent.children = append(parent.children, entryNum)
		}
	}
	computeCumulativeSizes(prevNodes)

	// Build result
	absPath := strings.ToUpper(driveLetter) + `:\`
	usage, _ := disk.Usage(absPath)
	var totalBytes, freeBytes, usedBytes int64
	if usage != nil {
		totalBytes = int64(usage.Total)
		freeBytes = int64(usage.Free)
		usedBytes = int64(usage.Used)
	}

	rootEntry := uint64(5)
	rootNode, ok := prevNodes[rootEntry]
	if !ok {
		return nil, fmt.Errorf("root entry not found")
	}

	topN := opts.TopN
	if topN <= 0 {
		topN = 20
	}
	h := NewTopN(topN)
	for _, childNum := range rootNode.children {
		child, ok := prevNodes[childNum]
		if !ok || !child.inUse {
			continue
		}
		if childNum <= 23 && strings.HasPrefix(child.name, "$") {
			continue
		}
		h.Add(DirEntry{
			Path:         absPath + child.name,
			SizeBytes:    child.cumSize,
			IsDir:        child.isDir,
			ChildCount:   len(child.children),
			LastModified: child.lastMod,
		})
	}

	return &ScanResult{
		RootPath:     absPath,
		TotalBytes:   totalBytes,
		FreeBytes:    freeBytes,
		UsedBytes:    usedBytes,
		Entries:      h.Sorted(),
		ScanCoverage: 1.0,
		DurationMs:   time.Since(startTime).Milliseconds(),
		EngineName:   "usn-incremental",
	}, nil
}

// ntfsBootstrapResult holds the minimal context from go-ntfs bootstrap.
type ntfsBootstrapResult struct {
	mftReader  interface{ ReadAt([]byte, int64) (int, error) }
	recordSize int64
}

// ntfsBootstrapOnly uses go-ntfs only for locating $MFT, then closes context.
func ntfsBootstrapOnly(reader *sectorAlignedReader) (*ntfsBootstrapResult, error) {
	ctx, err := ntfs.GetNTFSContext(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("NTFS bootstrap: %w", err)
	}
	recordSize := ctx.RecordSize
	if recordSize <= 0 {
		recordSize = 1024
	}
	mftReader, err := ntfs.BootstrapMFT(ctx)
	ctx.Close()
	if err != nil {
		return nil, fmt.Errorf("MFT bootstrap: %w", err)
	}
	return &ntfsBootstrapResult{mftReader: mftReader, recordSize: recordSize}, nil
}

// sortUint64 sorts a uint64 slice in ascending order.
// Full-permutation optimization: sorted access pattern gives sequential I/O.
func sortUint64(s []uint64) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}
