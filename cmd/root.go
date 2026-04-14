package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

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
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
