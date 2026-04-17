package cmd

import (
	"fmt"
	"strings"
	"time"

	"distrike/config"
	"distrike/hunter"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/output"
	"distrike/scanner"

	"github.com/spf13/cobra"
)

var (
	huntRisk   string
	huntAll    bool
	huntAfter  string
	huntBefore string
)

var huntCmd = &cobra.Command{
	Use:   "hunt [path...]",
	Short: "Identify cleanable prey with risk assessment and cleanup commands",
	Long:  `Scan and automatically identify prey (cleanable items) using built-in rules for caches, temp files, virtual disks, backups, downloads, and orphans. Each prey includes risk level and actionable cleanup command.`,
	RunE:  runHunt,
}

func init() {
	huntCmd.Flags().StringVar(&huntRisk, "risk", "all", "filter by risk level: all/safe/caution/danger")
	huntCmd.Flags().BoolVar(&huntAll, "all", false, "hunt all drives/mount points")
	huntCmd.Flags().StringVar(&huntAfter, "after", "", "only show entries modified after (td/yd/3d/7d/tw/lw/tm/@timestamp/YYYY-MM-DD)")
	huntCmd.Flags().StringVar(&huntBefore, "before", "", "only show entries modified before")
	rootCmd.AddCommand(huntCmd)
}

func runHunt(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine scan paths (normalize Windows drive letters like D: → D:\)
	paths := make([]string, len(args))
	for i, a := range args {
		paths[i] = units.NormalizePath(a)
	}
	if len(paths) == 0 || huntAll {
		drives, err := killline.EnumerateDrives()
		if err != nil {
			return fmt.Errorf("enumerating drives: %w", err)
		}
		for _, d := range drives {
			paths = append(paths, d.Path)
		}
	}

	// Parse time filters
	var afterTime, beforeTime time.Time
	if huntAfter != "" {
		t, err := units.ParseDateShortcut(huntAfter)
		if err != nil {
			return fmt.Errorf("parsing --after %q: %w", huntAfter, err)
		}
		afterTime = t
	}
	if huntBefore != "" {
		t, err := units.ParseDateShortcut(huntBefore)
		if err != nil {
			return fmt.Errorf("parsing --before %q: %w", huntBefore, err)
		}
		beforeTime = t
	}

	minScanSize, _ := units.ParseSize(cfg.Scan.MinSize)
	// Hunt needs deeper scan than normal scan — caches live at depth 5-6+
	// e.g., C:\Users\asus\AppData\Local\pip\cache (depth 6)
	// e.g., D:\LDPlayer\LDPlayer9\vms\leidian0\data.vmdk (depth 4)
	huntDepth := cfg.Scan.MaxDepth
	if huntDepth < 10 {
		huntDepth = 10
	}
	var collectExts []string
	if cfg.Hunt.ScanModelWeights {
		collectExts = []string{
			".safetensors", ".gguf", ".ggml",
			".pt", ".pth", ".ckpt",
			".h5", ".hdf5", ".onnx", ".pb",
		}
	}
	scanOpts := scanner.ScanOptions{
		MaxDepth:        huntDepth,
		MinSize:         minScanSize,
		TopN:            500, // scan more for hunting
		FollowSymlinks:  cfg.Scan.FollowSymlinks,
		Workers:         cfg.Scan.Workers,
		Exclude:         cfg.Scan.Exclude,
		CollectAll:      true, // collect all dirs, not just top-level
		CollectFileExts: collectExts,
		AfterTime:       afterTime,
		BeforeTime:      beforeTime,
	}

	// Collect all entries from scans
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

	// Load rules
	var rules []hunter.Rule
	if cfg.Hunt.BuiltinRules {
		rules = append(rules, hunter.BuiltinRules()...)
	}
	if cfg.Hunt.ScanModelWeights {
		rules = append(rules, hunter.ModelWeightRules()...)
	}

	// Match entries against rules
	minPreySize, _ := units.ParseSize(cfg.Hunt.MinPreySize)
	matcher := hunter.NewMatcher(rules, cfg.Whitelist, minPreySize)
	prey := matcher.Match(allEntries)

	// MSCM-based app discovery: find known apps in non-standard install locations
	// (e.g. D:\软件\Chrome\ instead of Program Files\Google\Chrome\).
	// Runs after rule matching to avoid double-counting, then deduplicates.
	var appDiscDirs []string
	seen := make(map[string]bool)
	for _, p := range prey {
		seen[p.Path] = true
	}
	for _, e := range allEntries {
		if e.IsDir {
			appDiscDirs = append(appDiscDirs, e.Path)
		}
	}
	if len(appDiscDirs) > 0 {
		discovered := hunter.AppDiscover(appDiscDirs, minPreySize)
		for _, d := range discovered {
			if !seen[d.Path] {
				seen[d.Path] = true
				prey = append(prey, d)
			}
		}
	}

	// Detect Docker if enabled
	if cfg.Docker.Enabled {
		dd := &hunter.DockerDetector{}
		dockerPrey, _, _ := dd.Detect()
		prey = append(prey, dockerPrey...)
	}

	// Filter by --risk flag
	if huntRisk != "all" {
		var filtered []hunter.Prey
		for _, p := range prey {
			if strings.EqualFold(string(p.Risk), huntRisk) {
				filtered = append(filtered, p)
			}
		}
		prey = filtered
	}

	// Build summary
	summary := output.HuntSummary{
		TotalPrey: len(prey),
	}
	for _, p := range prey {
		summary.TotalBytes += p.SizeBytes
		switch p.Risk {
		case hunter.RiskSafe:
			summary.SafeCount++
			summary.SafeBytes += p.SizeBytes
		case hunter.RiskCaution:
			summary.CautionCount++
			summary.CautionBytes += p.SizeBytes
		case hunter.RiskDanger:
			summary.DangerCount++
			summary.DangerBytes += p.SizeBytes
		}
	}
	summary.TotalHuman = units.FormatSize(summary.TotalBytes)

	huntOut := output.HuntOutput{
		Data: output.HuntData{
			Prey:    prey,
			Summary: summary,
		},
	}

	fmt.Println(output.RenderHunt(huntOut, output.FormatFromFlags(jsonOutput, formatFlag)))
	return nil
}
