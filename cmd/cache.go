package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"distrike/config"
	"distrike/internal/units"
	"distrike/scanner"

	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage scan cache",
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear [path...]",
	Short: "Clear scan cache for specified paths, or entire cache if no path given",
	RunE:  runCacheClear,
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

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

	// No paths given — wipe the entire cache file
	if len(args) == 0 {
		if _, err := os.Stat(cachePath); os.IsNotExist(err) {
			fmt.Println("Cache is already empty.")
			return nil
		}
		if err := os.Remove(cachePath); err != nil {
			return fmt.Errorf("removing cache file: %w", err)
		}
		fmt.Printf("Cache cleared: %s\n", cachePath)
		return nil
	}

	// Paths given — open DB and invalidate each path
	ttl, ttlErr := units.ParseDuration(cfg.Cache.TTL)
	if ttlErr != nil {
		return fmt.Errorf("parsing cache TTL: %w", ttlErr)
	}
	cache, err := scanner.NewCache(cachePath, ttl)
	if err != nil {
		return fmt.Errorf("opening cache: %w", err)
	}
	defer cache.Close()

	for _, p := range args {
		abs, err := filepath.Abs(p)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: resolving %s: %v\n", p, err)
			continue
		}
		if err := cache.Invalidate(abs); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: clearing cache for %s: %v\n", abs, err)
			continue
		}
		fmt.Printf("Cleared: %s\n", abs)
	}
	return nil
}
