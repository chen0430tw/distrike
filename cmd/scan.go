package cmd

import (
	"fmt"

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

	opts := scanner.ScanOptions{
		MaxDepth:       scanDepth,
		MinSize:        minSize,
		TopN:           scanTop,
		FollowSymlinks: cfg.Scan.FollowSymlinks,
		Workers:        cfg.Scan.Workers,
		Exclude:        cfg.Scan.Exclude,
	}

	for _, path := range paths {
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
