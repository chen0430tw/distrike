package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"distrike/config"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/output"
	"distrike/scanner"

	"github.com/spf13/cobra"
)

var (
	scanTop     int
	scanMinSize string
	scanDepth   int
	scanEngine  string
	scanNoCache bool
	scanAfter   string
	scanBefore  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path...]",
	Short: "Scan directories and show top space consumers",
	Long:  `Scan specified paths (or all drives) and output the largest directories sorted by size. Supports multiple scan engines: fastwalk (default), MFT direct-read (Windows Admin).`,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().IntVar(&scanTop, "top", 20, "number of top entries to show")
	scanCmd.Flags().StringVar(&scanMinSize, "min-size", "100MB", "minimum size to display")
	scanCmd.Flags().IntVar(&scanDepth, "depth", 3, "maximum directory depth")
	scanCmd.Flags().StringVar(&scanEngine, "engine", "auto", "scan engine: auto/fastwalk/mft")
	scanCmd.Flags().BoolVar(&scanNoCache, "no-cache", false, "skip scan cache")
	scanCmd.Flags().StringVar(&scanAfter, "after", "", "only show entries modified after (td/yd/3d/7d/tw/lw/tm/@timestamp/YYYY-MM-DD)")
	scanCmd.Flags().StringVar(&scanBefore, "before", "", "only show entries modified before")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine scan paths (normalize Windows drive letters like D: → D:\)
	paths := make([]string, len(args))
	for i, a := range args {
		paths[i] = units.NormalizePath(a)
	}
	if len(paths) == 0 {
		drives, err := killline.EnumerateDrives()
		if err != nil {
			return fmt.Errorf("enumerating drives: %w", err)
		}
		for _, d := range drives {
			paths = append(paths, d.Path)
		}
	}

	minSize, err := units.ParseSize(scanMinSize)
	if err != nil {
		return fmt.Errorf("parsing min-size %q: %w", scanMinSize, err)
	}

	// Parse time filters
	var afterTime, beforeTime time.Time
	if scanAfter != "" {
		t, err := units.ParseDateShortcut(scanAfter)
		if err != nil {
			return fmt.Errorf("parsing --after %q: %w", scanAfter, err)
		}
		afterTime = t
	}
	if scanBefore != "" {
		t, err := units.ParseDateShortcut(scanBefore)
		if err != nil {
			return fmt.Errorf("parsing --before %q: %w", scanBefore, err)
		}
		beforeTime = t
	}

	opts := scanner.ScanOptions{
		MaxDepth:       scanDepth,
		MinSize:        minSize,
		TopN:           scanTop,
		FollowSymlinks: cfg.Scan.FollowSymlinks,
		Workers:        cfg.Scan.Workers,
		Exclude:        cfg.Scan.Exclude,
	}

	// Set up cache if enabled
	var cache *scanner.Cache
	useCache := cfg.Cache.Enabled && !scanNoCache
	if useCache {
		cachePath := cfg.Cache.Path
		if cachePath == "auto" || cachePath == "" {
			var cacheDir string
			switch runtime.GOOS {
			case "windows":
				cacheDir = filepath.Join(os.Getenv("APPDATA"), "distrike")
			default:
				home, _ := os.UserHomeDir()
				cacheDir = filepath.Join(home, ".cache", "distrike")
			}
			cachePath = filepath.Join(cacheDir, "scan_cache.db")
		}

		ttl, ttlErr := units.ParseDuration(cfg.Cache.TTL)
		if ttlErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: invalid cache TTL %q, disabling cache: %v\n", cfg.Cache.TTL, ttlErr)
			useCache = false
		} else {
			c, cacheErr := scanner.NewCache(cachePath, ttl)
			if cacheErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to open cache: %v\n", cacheErr)
				useCache = false
			} else {
				cache = c
				defer cache.Close()
			}
		}
	}

	for _, path := range paths {
		// Try loading from cache first
		if useCache && cache != nil {
			cached, cacheErr := cache.Load(path)
			if cacheErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cache load error for %s: %v\n", path, cacheErr)
			} else if cached != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Using cached result for %s\n", path)
				result := cached
				scanOut := output.ScanOutput{
					Data: output.ScanData{
						RootPath:     result.RootPath,
						TotalBytes:   result.TotalBytes,
						FreeBytes:    result.FreeBytes,
						UsedBytes:    result.UsedBytes,
						ScanCoverage: result.ScanCoverage,
						DurationMs:   result.DurationMs,
						EngineName:   result.EngineName,
					},
				}
				for _, e := range result.Entries {
					if e.SizeBytes < minSize {
						continue
					}
					if !afterTime.IsZero() && e.LastModified.Before(afterTime) {
						continue
					}
					if !beforeTime.IsZero() && e.LastModified.After(beforeTime) {
						continue
					}
					scanOut.Data.Entries = append(scanOut.Data.Entries, output.ScanEntry{
						Path:      e.Path,
						SizeBytes: e.SizeBytes,
						SizeHuman: units.FormatSize(e.SizeBytes),
						IsDir:     e.IsDir,
						Children:  e.ChildCount,
					})
				}
				fmt.Println(output.RenderScan(scanOut, jsonOutput))
				continue
			}
		}

		eng := scanner.SelectEngine(path, scanEngine)
		if eng == nil {
			eng = &scanner.FastwalkEngine{}
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "Scanning %s (engine: %s)...\n", path, eng.Name())

		result, err := eng.Scan(path, opts)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error scanning %s: %v\n", path, err)
			continue
		}

		// Save to cache
		if useCache && cache != nil {
			if saveErr := cache.Save(result); saveErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to save cache for %s: %v\n", path, saveErr)
			}
		}

		scanOut := output.ScanOutput{
			Data: output.ScanData{
				RootPath:     result.RootPath,
				TotalBytes:   result.TotalBytes,
				FreeBytes:    result.FreeBytes,
				UsedBytes:    result.UsedBytes,
				ScanCoverage: result.ScanCoverage,
				DurationMs:   result.DurationMs,
				EngineName:   result.EngineName,
			},
		}

		for _, e := range result.Entries {
			if e.SizeBytes < minSize {
				continue
			}
			if !afterTime.IsZero() && e.LastModified.Before(afterTime) {
				continue
			}
			if !beforeTime.IsZero() && e.LastModified.After(beforeTime) {
				continue
			}
			scanOut.Data.Entries = append(scanOut.Data.Entries, output.ScanEntry{
				Path:      e.Path,
				SizeBytes: e.SizeBytes,
				SizeHuman: units.FormatSize(e.SizeBytes),
				IsDir:     e.IsDir,
				Children:  e.ChildCount,
			})
		}

		fmt.Println(output.RenderScan(scanOut, jsonOutput))
	}

	return nil
}
