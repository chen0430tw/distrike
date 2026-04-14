package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charlievieth/fastwalk"
	"github.com/shirou/gopsutil/v3/disk"
)

// FastwalkEngine uses charlievieth/fastwalk for concurrent directory traversal.
// ~6x faster than filepath.WalkDir on Windows, ~4x on Linux.
type FastwalkEngine struct{}

func (e *FastwalkEngine) Name() string { return "fastwalk" }

func (e *FastwalkEngine) Scan(path string, opts ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	// Normalize path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path %s: %w", path, err)
	}

	// Get disk usage info
	usage, err := disk.Usage(absPath)
	if err != nil {
		return nil, fmt.Errorf("getting disk usage for %s: %w", absPath, err)
	}

	// Determine worker count based on storage type
	workers := opts.Workers
	if workers <= 0 {
		switch detectStorageType(absPath) {
		case StorageHDD:
			workers = 1
		case StorageSSD:
			workers = runtime.GOMAXPROCS(0) * 2
		default:
			// Unknown storage — conservative default
			workers = runtime.GOMAXPROCS(0)
		}
	}

	// Build exclude set for fast lookup
	excludeSet := make(map[string]bool, len(opts.Exclude))
	for _, ex := range opts.Exclude {
		excludeSet[strings.ToLower(ex)] = true
	}

	// Track top-level (depth 1) directory sizes
	// key = top-level entry path, value = accumulated size
	type dirInfo struct {
		size       int64
		childCount int32
		lastMod    time.Time
		isDir      bool
	}

	var mu sync.Mutex
	topLevel := make(map[string]*dirInfo)

	var deniedPaths []string
	var deniedMu sync.Mutex

	var scannedCount int64
	var deniedCount int64

	rootDepth := strings.Count(filepath.ToSlash(absPath), "/")

	// CollectAll mode: also track every directory for rule matching (hunt)
	var allDirs []DirEntry
	var allDirsMu sync.Mutex

	conf := fastwalk.Config{
		NumWorkers: workers,
		Follow:     opts.FollowSymlinks,
	}

	walkErr := fastwalk.Walk(&conf, absPath, func(entryPath string, d os.DirEntry, err error) error {
		if err != nil {
			// Access denied or other permission error — record and continue
			deniedMu.Lock()
			deniedPaths = append(deniedPaths, entryPath)
			deniedMu.Unlock()
			atomic.AddInt64(&deniedCount, 1)
			return nil
		}

		// Calculate depth relative to root
		rel := filepath.ToSlash(entryPath)
		depth := strings.Count(rel, "/") - rootDepth
		if depth <= 0 {
			// Root itself
			return nil
		}

		// MaxDepth: controls display grouping, NOT traversal depth.
		// We always traverse all files to accumulate correct sizes,
		// but only create separate top-level entries for depth <= MaxDepth.
		// Files beyond MaxDepth still contribute to their ancestor's size.

		// Check exclusions on base name
		baseName := strings.ToLower(filepath.Base(entryPath))
		if excludeSet[baseName] {
			if d.IsDir() {
				return fastwalk.SkipDir
			}
			return nil
		}

		atomic.AddInt64(&scannedCount, 1)

		info, infoErr := d.Info()
		var fileSize int64
		var modTime time.Time
		if infoErr == nil {
			if !d.IsDir() {
				fileSize = info.Size()
			}
			modTime = info.ModTime()

			// Time filter: only count files within the time window.
			// Directories always pass (their cumulative size comes from their files).
			if !d.IsDir() && fileSize > 0 {
				if !opts.AfterTime.IsZero() && modTime.Before(opts.AfterTime) {
					fileSize = 0 // exclude from size accumulation
				}
				if !opts.BeforeTime.IsZero() && modTime.After(opts.BeforeTime) {
					fileSize = 0
				}
			}
		}

		// CollectAll: record directories + virtual disk files for hunt rule matching
		if opts.CollectAll {
			isVDisk := !d.IsDir() && isVDiskExt(baseName)
			if d.IsDir() || isVDisk {
				allDirsMu.Lock()
				allDirs = append(allDirs, DirEntry{
					Path:         entryPath,
					SizeBytes:    fileSize, // non-zero for vdisk files
					IsDir:        d.IsDir(),
					LastModified: modTime,
				})
				allDirsMu.Unlock()
			}
		}

		// Determine which top-level entry this belongs to
		// Top-level = depth 1 relative to absPath
		relPath, _ := filepath.Rel(absPath, entryPath)
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 2)
		topKey := filepath.Join(absPath, parts[0])

		mu.Lock()
		di, exists := topLevel[topKey]
		if !exists {
			isDir := false
			if depth == 1 {
				isDir = d.IsDir()
			} else {
				// Top-level entry is a directory since we're inside it
				isDir = true
			}
			di = &dirInfo{isDir: isDir}
			topLevel[topKey] = di
		}
		di.size += fileSize
		if depth == 1 {
			// Update last modified for the top-level entry itself
			if modTime.After(di.lastMod) {
				di.lastMod = modTime
			}
		}
		di.childCount++
		mu.Unlock()

		return nil
	})

	if walkErr != nil {
		return nil, fmt.Errorf("scanning %s: %w", absPath, walkErr)
	}

	// Build entries from top-level map
	topN := opts.TopN
	if topN <= 0 {
		topN = 20
	}
	h := NewTopN(topN)

	for entryPath, di := range topLevel {
		entry := DirEntry{
			Path:         entryPath,
			SizeBytes:    di.size,
			IsDir:        di.isDir,
			ChildCount:   int(di.childCount),
			LastModified: di.lastMod,
		}
		h.Add(entry)
	}

	// Compute scan coverage
	total := atomic.LoadInt64(&scannedCount) + atomic.LoadInt64(&deniedCount)
	var coverage float64
	if total > 0 {
		coverage = float64(atomic.LoadInt64(&scannedCount)) / float64(total)
	} else {
		coverage = 1.0
	}

	// Build final entry list
	var entries []DirEntry
	if opts.CollectAll {
		// Hunt mode: return top-level entries + all discovered directories
		entries = h.Sorted()
		entries = append(entries, allDirs...)
	} else {
		entries = h.Sorted()
	}

	result := &ScanResult{
		RootPath:     absPath,
		TotalBytes:   int64(usage.Total),
		FreeBytes:    int64(usage.Free),
		UsedBytes:    int64(usage.Used),
		Entries:      entries,
		DeniedPaths:  deniedPaths,
		ScanCoverage: coverage,
		DurationMs:   time.Since(startTime).Milliseconds(),
		EngineName:   e.Name(),
	}

	return result, nil
}

// isVDiskExt checks if a filename has a virtual disk extension.
func isVDiskExt(name string) bool {
	for _, ext := range []string{".vhdx", ".vmdk", ".vdi", ".qcow2"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
