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
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate("distrike {{.Version}}\n")
}
