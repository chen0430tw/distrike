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

	// Determine worker count
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0) * 2
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

		// Check MaxDepth
		if opts.MaxDepth > 0 && depth > opts.MaxDepth {
			if d.IsDir() {
				return fastwalk.SkipDir
			}
			return nil
		}

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
		}

		// CollectAll: record every directory for hunt rule matching
		if opts.CollectAll && d.IsDir() {
			allDirsMu.Lock()
			allDirs = append(allDirs, DirEntry{
				Path:         entryPath,
				SizeBytes:    0, // will be set to accumulated size below if top-level
				IsDir:        true,
				LastModified: modTime,
			})
			allDirsMu.Unlock()
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
