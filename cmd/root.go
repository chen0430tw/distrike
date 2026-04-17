package cmd

import (
	"fmt"
	"os"

	"distrike/output"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var (
	jsonOutput bool
	verbose    bool
	formatFlag string
)

var rootCmd = &cobra.Command{
	Use:   "distrike",
	Short: "Cross-platform disk space kill-line detector",
	Long: `Distrike - Disk + Strike

A cross-platform, Agent-friendly disk space analyzer with kill-line alerts,
four-color capacity signals, and automated prey identification.

Distrike answers: "What should be cleaned? How long until danger? Is it critical?"`,
}

func Execute() {
	output.ToolVersion = Version
	// Assign -v shorthand to --version (must be after cobra registers the flag)
	if f := rootCmd.Flags().Lookup("version"); f != nil {
		f.Shorthand = "v"
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print Distrike version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("distrike " + Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format (shorthand for --format=json)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&formatFlag, "format", "", "output format: auto|table|tsv|json (default: auto — table on TTY, TSV on pipe)")
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("distrike {{.Version}}\n")
}
