package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"distrike/config"
	"distrike/internal/units"
	"distrike/killline"
	"distrike/scanner"
	"distrike/signal"

	"github.com/spf13/cobra"
)

var (
	topoDepth int
	topoMin   string
)

var topoCmd = &cobra.Command{
	Use:   "topo [path]",
	Short: "Trace where space flows — find the deepest sinks",
	Long: `Topology view of disk space usage. Built on Tensorearch's
node-edge-weight propagation graph.

As Admin: full critical path trace — drills into the largest directory
chain from root to the deepest space sink, with cumulative sizes from
the MFT engine.

Without Admin: top-level directory breakdown only (no drill-down).
Run as Administrator for the complete topology.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTopo,
}

func init() {
	topoCmd.Flags().IntVar(&topoDepth, "depth", 4, "max drill-down depth")
	topoCmd.Flags().StringVar(&topoMin, "min", "5%", "minimum percentage to display (e.g. 5%, 1GB)")
	rootCmd.AddCommand(topoCmd)
}

func runTopo(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Determine target path
	var targetPath string
	if len(args) > 0 {
		targetPath = units.NormalizePath(args[0])
	} else {
		// Default: worst signal drive
		drives, err := killline.EnumerateDrives()
		if err != nil {
			return fmt.Errorf("enumerating drives: %w", err)
		}
		killLineBytes, _ := units.ParseSize(cfg.KillLine)
		thresholds := signal.DefaultThresholds()
		// Pick worst non-removable drive first; fall back to any worst drive
		worstFixed := -1
		worstAny := -1
		var fixedPath, anyPath string
		for _, d := range drives {
			var r float64
			if d.TotalBytes > 0 {
				r = float64(d.UsedBytes) / float64(d.TotalBytes)
			}
			sig := signal.Classify(r, 0, d.FreeBytes, d.TotalBytes, killLineBytes, thresholds)
			lvl := topoSignalLevel(sig.Light)
			if lvl > worstAny {
				worstAny = lvl
				anyPath = d.Path
			}
			if !d.Removable && lvl > worstFixed {
				worstFixed = lvl
				fixedPath = d.Path
			}
		}
		if fixedPath != "" {
			targetPath = fixedPath
		} else {
			targetPath = anyPath
		}
	}
	if targetPath == "" {
		return fmt.Errorf("no drives found")
	}

	// Parse min threshold
	minPct := 5.0
	minAbs := int64(0)
	if strings.HasSuffix(topoMin, "%") {
		fmt.Sscanf(topoMin, "%f%%", &minPct)
	} else {
		minAbs, _ = units.ParseSize(topoMin)
	}

	killLineBytes, _ := units.ParseSize(cfg.KillLine)

	scanOpts := scanner.ScanOptions{
		MaxDepth:       20,
		MinSize:        0,
		TopN:           2000,
		FollowSymlinks: cfg.Scan.FollowSymlinks,
		Workers:        cfg.Scan.Workers,
		Exclude:        cfg.Scan.Exclude,
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Scanning %s...\n", targetPath)

	// Try MFT topology (Windows Admin + NTFS)
	root, result, err := scanner.ScanTopo(targetPath, scanOpts)
	if err != nil {
		return fmt.Errorf("scanning %s: %w", targetPath, err)
	}

	// Fallback to fastwalk if MFT unavailable
	if root == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "MFT unavailable, using fastwalk (run as Admin for full topology)...\n")
		eng := &scanner.FastwalkEngine{}
		scanOpts.CollectAll = true
		r, scanErr := eng.Scan(targetPath, scanOpts)
		if scanErr != nil {
			return fmt.Errorf("scanning %s: %w", targetPath, scanErr)
		}
		result = r
		root = buildFallbackTree(r.Entries, targetPath, r.UsedBytes)
	}

	if root == nil {
		return fmt.Errorf("no data for %s", targetPath)
	}

	// Signal for header
	thresholds := signal.DefaultThresholds()
	var usedRatio float64
	if result.TotalBytes > 0 {
		usedRatio = float64(result.UsedBytes) / float64(result.TotalBytes)
	}
	sig := signal.Classify(usedRatio, 0, result.FreeBytes, result.TotalBytes, killLineBytes, thresholds)

	// Color codes
	const reset = "\033[0m"
	sigColor := topoColor(sig.Light)
	sigName := topoSignalName(sig.Light)

	totalSize := root.Size
	if totalSize == 0 {
		totalSize = result.UsedBytes
	}
	minBytes := int64(float64(totalSize) * minPct / 100)
	if minAbs > 0 {
		minBytes = minAbs
	}

	// Find sink first so we can put the verdict in the header
	sort.Slice(root.Children, func(i, j int) bool {
		return root.Children[i].Size > root.Children[j].Size
	})
	const barMax = 45
	sinkNode := findSink(root, topoDepth)

	// === Header with verdict ===
	fmt.Printf("\n  %s  %s used, %s free  %s%s%s\n",
		targetPath,
		units.FormatSize(result.UsedBytes),
		units.FormatSize(result.FreeBytes),
		sigColor, sigName, reset,
	)
	if sinkNode != nil && totalSize > 0 {
		pct := float64(sinkNode.Size) / float64(totalSize) * 100
		if pct >= 3 { // only show verdict if sink is significant
			fmt.Printf("  %s%s is eating %.0f%% (%s)%s\n",
				sigColor, sinkNode.Name, pct, units.FormatSize(sinkNode.Size), reset)
		}
	}

	// Check if tree has depth (MFT) or is flat (fastwalk fallback)
	hasDepth := false
	for _, c := range root.Children {
		if len(c.Children) > 0 {
			hasDepth = true
			break
		}
	}

	fmt.Println()
	if hasDepth {
		// === Critical path (MFT mode) ===
		traceCriticalPath(root, totalSize, barMax, topoDepth)
		fmt.Println()

		// === Other branches ===
		for i, child := range root.Children {
			if i == 0 || !child.IsDir || child.Size < minBytes {
				continue
			}
			pct := float64(child.Size) / float64(totalSize) * 100
			barLen := int(pct / 100 * float64(barMax))
			if barLen < 1 {
				barLen = 1
			}
			fmt.Printf("  %-22s %8s  %s %4.0f%%\n",
				child.Name,
				units.FormatSize(child.Size),
				strings.Repeat("━", barLen),
				pct,
			)
		}
	} else {
		// === Flat mode (fastwalk fallback) — show all significant entries ===
		for _, child := range root.Children {
			if child.Size < minBytes {
				continue
			}
			pct := float64(child.Size) / float64(totalSize) * 100
			barLen := int(pct / 100 * float64(barMax))
			if barLen < 1 {
				barLen = 1
			}
			fmt.Printf("  %4.0f%%  %s %-22s %8s\n",
				pct,
				strings.Repeat("━", barLen),
				child.Name,
				units.FormatSize(child.Size),
			)
		}
	}
	// (skip the old "Other branches" block below)
	fmt.Println()
	return nil
}


// traceCriticalPath prints the critical path — one line per hop, traceroute-style.
// Skips the root itself; starts from the first meaningful directory.
func traceCriticalPath(root *scanner.TopoNode, totalSize int64, barMax, maxDepth int) {
	current := root

	for depth := 0; depth < maxDepth; depth++ {
		if len(current.Children) == 0 {
			return
		}

		sort.Slice(current.Children, func(i, j int) bool {
			return current.Children[i].Size > current.Children[j].Size
		})

		// Pick largest dir child
		var next *scanner.TopoNode
		for _, c := range current.Children {
			if c.IsDir && c.Size > 0 {
				next = c
				break
			}
		}
		if next == nil || float64(next.Size)/float64(totalSize)*100 < 3 {
			return
		}

		pct := float64(next.Size) / float64(totalSize) * 100
		barLen := int(pct / 100 * float64(barMax))
		if barLen < 1 {
			barLen = 1
		}

		indent := strings.Repeat("  ", depth)
		connector := "└"
		if depth == 0 {
			connector = " "
		}
		isSink := true
		for _, c := range next.Children {
			if c.IsDir && float64(c.Size)/float64(totalSize)*100 >= 3 {
				isSink = false
				break
			}
		}

		marker := ""
		if isSink || depth == maxDepth-1 {
			marker = " ◀"
		}

		fmt.Printf("  %s%s %s %-20s %8s  %4.0f%%%s\n",
			indent, connector,
			strings.Repeat("━", barLen),
			next.Name,
			units.FormatSize(next.Size),
			pct,
			marker,
		)
		if !isSink && depth < maxDepth-1 {
			fmt.Printf("  %s│\n", strings.Repeat("  ", depth+1))
		}

		current = next
	}
}

// findSink traces the critical path without printing, returns the deepest node.
func findSink(root *scanner.TopoNode, maxDepth int) *scanner.TopoNode {
	current := root
	for depth := 0; depth < maxDepth; depth++ {
		if len(current.Children) == 0 {
			return current
		}
		sort.Slice(current.Children, func(i, j int) bool {
			return current.Children[i].Size > current.Children[j].Size
		})
		var next *scanner.TopoNode
		for _, c := range current.Children {
			if c.IsDir && c.Size > 0 {
				next = c
				break
			}
		}
		if next == nil {
			return current
		}
		current = next
	}
	return current
}

// buildFallbackTree builds a simple tree from fastwalk flat entries (non-MFT fallback).
func buildFallbackTree(entries []scanner.DirEntry, rootPath string, totalUsed int64) *scanner.TopoNode {
	// Normalize rootPath to end with separator for clean name extraction
	cleanRoot := strings.TrimRight(rootPath, `\/`) + string(filepath.Separator)

	root := &scanner.TopoNode{
		Name:  rootPath,
		Path:  rootPath,
		Size:  totalUsed,
		IsDir: true,
	}
	for _, e := range entries {
		if e.SizeBytes > 0 {
			name := strings.TrimPrefix(e.Path, cleanRoot)
			if name == "" || name == e.Path {
				name = filepath.Base(e.Path)
			}
			root.Children = append(root.Children, &scanner.TopoNode{
				Name:  name,
				Path:  e.Path,
				Size:  e.SizeBytes,
				IsDir: e.IsDir,
			})
		}
	}
	return root
}

func topoSignalLevel(l signal.Light) int {
	switch l {
	case signal.Purple:
		return 3
	case signal.Red:
		return 2
	case signal.Yellow:
		return 1
	default:
		return 0
	}
}

func topoSignalName(l signal.Light) string {
	switch l {
	case signal.Purple:
		return "CRITICAL"
	case signal.Red:
		return "DANGER"
	case signal.Yellow:
		return "WARNING"
	case signal.Green:
		return "OK"
	default:
		return ""
	}
}

func topoColor(l signal.Light) string {
	switch l {
	case signal.Purple:
		return "\033[38;2;147;51;234m"
	case signal.Red:
		return "\033[38;2;218;38;38m"
	case signal.Yellow:
		return "\033[38;2;255;193;7m"
	case signal.Green:
		return "\033[38;2;50;205;50m"
	default:
		return ""
	}
}
