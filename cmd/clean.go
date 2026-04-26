package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"distrike/cleaner"
	"distrike/config"
	"distrike/hunter"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/output"
	"distrike/scanner"
	"distrike/vdisk"

	"github.com/spf13/cobra"
)

var (
	cleanRisk   string
	cleanDryRun bool
	cleanYes    bool
	cleanTarget []string
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Execute cleanup based on hunt results",
	Long:  `Execute cleanup commands for identified prey. Supports dry-run preview, risk filtering, and silent mode for Agent automation.`,
	RunE:  runClean,
}

func init() {
	cleanCmd.Flags().StringVar(&cleanRisk, "risk", "safe", "only clean prey at this risk level: safe/caution")
	cleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "preview only, do not execute")
	cleanCmd.Flags().BoolVar(&cleanYes, "yes", false, "skip confirmation (for Agent use)")
	cleanCmd.Flags().StringSliceVar(&cleanTarget, "target", nil, "clean specific prey by name")
	rootCmd.AddCommand(cleanCmd)
}

func runClean(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Run hunt to get prey list
	drives, err := killline.EnumerateDrives()
	if err != nil {
		return fmt.Errorf("enumerating drives: %w", err)
	}

	var paths []string
	for _, d := range drives {
		paths = append(paths, d.Path)
	}

	minScanSize, _ := units.ParseSize(cfg.Scan.MinSize)
	// Must match hunt scan parameters so prey is found consistently
	huntDepth := cfg.Scan.MaxDepth
	if huntDepth < 10 {
		huntDepth = 10
	}
	scanOpts := scanner.ScanOptions{
		MaxDepth:       huntDepth,
		MinSize:        minScanSize,
		TopN:           500,
		FollowSymlinks: cfg.Scan.FollowSymlinks,
		Workers:        cfg.Scan.Workers,
		Exclude:        cfg.Scan.Exclude,
		CollectAll:     true,
	}

	var allEntries []scanner.DirEntry
	for _, path := range paths {
		eng, engNote := scanner.SelectEngine(path, cfg.Scan.Engine)
		if eng == nil {
			eng = &scanner.FastwalkEngine{}
		}
		if engNote != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Note: %s\n", engNote)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Scanning %s...\n", path)
		result, err := eng.Scan(path, scanOpts)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error scanning %s: %v\n", path, err)
			continue
		}
		allEntries = append(allEntries, result.Entries...)
	}

	// Match
	var rules []hunter.Rule
	if cfg.Hunt.BuiltinRules {
		rules = append(rules, hunter.BuiltinRules()...)
	}
	minPreySize, _ := units.ParseSize(cfg.Hunt.MinPreySize)
	matcher := hunter.NewMatcher(rules, cfg.Whitelist, minPreySize)
	prey := matcher.Match(allEntries)

	// Detect Docker if enabled (must match hunt behavior)
	if cfg.Docker.Enabled {
		dd := &hunter.DockerDetector{}
		dockerPrey, _, _ := dd.Detect()
		prey = append(prey, dockerPrey...)
	}

	// Filter by --risk
	var filtered []hunter.Prey
	for _, p := range prey {
		if strings.EqualFold(string(p.Risk), cleanRisk) || cleanRisk == "all" {
			filtered = append(filtered, p)
		}
	}
	prey = filtered

	// Filter by --target
	if len(cleanTarget) > 0 {
		targetSet := make(map[string]bool)
		for _, t := range cleanTarget {
			targetSet[strings.ToLower(t)] = true
		}
		var targetFiltered []hunter.Prey
		for _, p := range prey {
			if targetSet[strings.ToLower(string(p.Kind))] || targetSet[strings.ToLower(p.Path)] {
				targetFiltered = append(targetFiltered, p)
			}
		}
		prey = targetFiltered
	}

	if len(prey) == 0 {
		fmt.Println("No prey found matching filters.")
		return nil
	}

	// Dry-run: show plan and exit
	if cleanDryRun {
		fmt.Println("Dry-run: the following items would be cleaned:")
		fmt.Println()
		var total int64
		for _, p := range prey {
			tag := "[" + strings.ToUpper(string(p.Risk)) + "]"
			fmt.Printf("  %s  %s  %s\n", tag, units.FormatSize(p.SizeBytes), p.Path)
			if p.Action.Type == "command" {
				fmt.Printf("    Command: %s\n", p.Action.Command)
			} else if p.Risk == hunter.RiskSafe {
				fmt.Printf("    Auto: clean-contents (delete directory contents)\n")
			} else {
				fmt.Printf("    Manual: %s\n", p.Action.Hint)
			}
			total += p.SizeBytes
		}
		fmt.Printf("\nTotal reclaimable: %s\n", units.FormatSize(total))
		return nil
	}

	// Confirmation prompt
	if !cleanYes {
		fmt.Printf("About to clean %d items. Continue? [y/N]: ", len(prey))
		var answer string
		fmt.Scanln(&answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Execute cleanup
	cleanOut := output.CleanOutput{
		Data: output.CleanData{},
	}

	for _, p := range prey {
		// Handle vdisk prey with compaction instead of command execution
		if p.Kind == hunter.KindVDisk {
			ext := strings.ToLower(filepath.Ext(p.Path))
			var before, after int64
			var compactErr error

			switch ext {
			case ".vhdx":
				fmt.Fprintf(cmd.ErrOrStderr(), "Compacting VHDX %s...\n", p.Path)
				before, after, compactErr = vdisk.CompactVHDX(p.Path)
			case ".vmdk":
				fmt.Fprintf(cmd.ErrOrStderr(), "Compacting VMDK %s...\n", p.Path)
				before, after, compactErr = vdisk.CompactVMDK(p.Path)
			case ".vdi":
				fmt.Fprintf(cmd.ErrOrStderr(), "Compacting VDI %s...\n", p.Path)
				before, after, compactErr = vdisk.CompactVDI(p.Path)
			default:
				fmt.Fprintf(cmd.ErrOrStderr(), "Skipping %s (unsupported vdisk format: %s)\n", p.Path, ext)
				continue
			}

			if compactErr != nil {
				errMsg := compactErr.Error()
				cleanOut.Data.Errors = append(cleanOut.Data.Errors, fmt.Sprintf("%s: %s", p.Path, errMsg))
				_ = cleaner.RecordHistory(p, 0, false, errMsg)
			} else {
				freed := before - after
				if freed < 0 {
					freed = 0
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "  %s -> %s (freed %s)\n", units.FormatSize(before), units.FormatSize(after), units.FormatSize(freed))
				item := output.CleanedItem{
					Path:       p.Path,
					SizeBytes:  p.SizeBytes,
					SizeHuman:  units.FormatSize(p.SizeBytes),
					Kind:       string(p.Kind),
					Risk:       string(p.Risk),
					Command:    "vdisk compact",
					FreedBytes: freed,
				}
				cleanOut.Data.FreedBytes += freed
				cleanOut.Data.Cleaned = append(cleanOut.Data.Cleaned, item)
				_ = cleaner.RecordHistory(p, freed, true, "")
			}
			continue
		}

		if p.Action.Type != "command" {
			// SAFE manual prey: auto-clean by deleting directory contents.
			// CAUTION/DANGER manual prey: still skip (needs user judgment).
			if p.Risk == hunter.RiskSafe {
				fmt.Fprintf(cmd.ErrOrStderr(), "Cleaning %s (contents)...\n", p.Path)
				freed, err := cleaner.CleanContents(p.Path)
				item := output.CleanedItem{
					Path:       p.Path,
					SizeBytes:  p.SizeBytes,
					SizeHuman:  units.FormatSize(p.SizeBytes),
					Kind:       string(p.Kind),
					Risk:       string(p.Risk),
					Command:    "clean-contents",
					FreedBytes: freed,
				}
				if err != nil {
					errMsg := err.Error()
					cleanOut.Data.Errors = append(cleanOut.Data.Errors, fmt.Sprintf("%s: %s", p.Path, errMsg))
					_ = cleaner.RecordHistory(p, freed, freed > 0, errMsg)
					if freed > 0 {
						cleanOut.Data.FreedBytes += freed
						cleanOut.Data.Cleaned = append(cleanOut.Data.Cleaned, item)
					}
				} else {
					cleanOut.Data.FreedBytes += freed
					cleanOut.Data.Cleaned = append(cleanOut.Data.Cleaned, item)
					_ = cleaner.RecordHistory(p, freed, true, "")
				}
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "Skipping %s (manual action: %s)\n", p.Path, p.Action.Hint)
			}
			continue
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "Cleaning %s...\n", p.Path)

		freed, err := cleaner.Execute(p)
		item := output.CleanedItem{
			Path:       p.Path,
			SizeBytes:  p.SizeBytes,
			SizeHuman:  units.FormatSize(p.SizeBytes),
			Kind:       string(p.Kind),
			Risk:       string(p.Risk),
			Command:    p.Action.Command,
			FreedBytes: freed,
		}

		if err != nil {
			errMsg := err.Error()
			cleanOut.Data.Errors = append(cleanOut.Data.Errors, fmt.Sprintf("%s: %s", p.Path, errMsg))
			_ = cleaner.RecordHistory(p, 0, false, errMsg)
		} else {
			cleanOut.Data.FreedBytes += freed
			cleanOut.Data.Cleaned = append(cleanOut.Data.Cleaned, item)
			_ = cleaner.RecordHistory(p, freed, true, "")
		}
	}

	cleanOut.Data.FreedHuman = units.FormatSize(cleanOut.Data.FreedBytes)

	result := output.RenderClean(cleanOut, output.FormatFromFlags(jsonOutput, formatFlag))
	fmt.Println(result)

	if len(cleanOut.Data.Errors) > 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "\nTip: Files locked by running programs (browsers, editors, etc.) cannot be cleaned.")
		fmt.Fprintln(cmd.ErrOrStderr(), "     Close those programs and re-run to free more space.")
		if cleanOut.Data.FreedBytes == 0 {
			os.Exit(2) // complete failure
		}
		// Partial success: some items cleaned, some failed — exit 0
	}
	return nil
}
