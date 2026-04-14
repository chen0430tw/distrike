package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"distrike/config"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View and modify Distrike configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration",
	RunE:  runConfigShow,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigGet,
}

var whitelistCmd = &cobra.Command{
	Use:   "whitelist",
	Short: "Manage whitelist entries",
}

var whitelistAddCmd = &cobra.Command{
	Use:   "add <path>",
	Short: "Add a path to the whitelist",
	Args:  cobra.ExactArgs(1),
	RunE:  runWhitelistAdd,
}

var whitelistRemoveCmd = &cobra.Command{
	Use:   "remove <path>",
	Short: "Remove a path from the whitelist",
	Args:  cobra.ExactArgs(1),
	RunE:  runWhitelistRemove,
}

var whitelistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all whitelist entries",
	RunE:  runWhitelistList,
}

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage custom prey rules",
}

var ruleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all custom rules",
	RunE:  runRuleList,
}

func init() {
	configCmd.AddCommand(configShowCmd, configSetCmd, configGetCmd)

	whitelistCmd.AddCommand(whitelistAddCmd, whitelistRemoveCmd, whitelistListCmd)
	configCmd.AddCommand(whitelistCmd)

	configCmd.AddCommand(ruleCmd)
	ruleCmd.AddCommand(ruleListCmd)

	rootCmd.AddCommand(configCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if jsonOutput {
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling config: %w", err)
		}
		fmt.Println(string(data))
	} else {
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshaling config: %w", err)
		}
		fmt.Print(string(data))
	}
	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := config.Set(cfg, key, value); err != nil {
		return fmt.Errorf("setting %s: %w", key, err)
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Set %s = %s\n", key, value)
	return nil
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	val, err := config.Get(cfg, key)
	if err != nil {
		return fmt.Errorf("getting %s: %w", key, err)
	}

	fmt.Println(val)
	return nil
}

func runWhitelistAdd(cmd *cobra.Command, args []string) error {
	path := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Check for duplicates
	for _, w := range cfg.Whitelist {
		if w == path {
			fmt.Printf("Path %q is already in the whitelist.\n", path)
			return nil
		}
	}

	cfg.Whitelist = append(cfg.Whitelist, path)

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Added %q to whitelist.\n", path)
	return nil
}

func runWhitelistRemove(cmd *cobra.Command, args []string) error {
	path := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	found := false
	var newList []string
	for _, w := range cfg.Whitelist {
		if strings.EqualFold(w, path) {
			found = true
			continue
		}
		newList = append(newList, w)
	}

	if !found {
		return fmt.Errorf("path %q not found in whitelist", path)
	}

	cfg.Whitelist = newList

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Removed %q from whitelist.\n", path)
	return nil
}

func runWhitelistList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if len(cfg.Whitelist) == 0 {
		fmt.Println("Whitelist is empty.")
		return nil
	}

	if jsonOutput {
		data, err := json.MarshalIndent(cfg.Whitelist, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling whitelist: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Println("Whitelist entries:")
		for i, w := range cfg.Whitelist {
			fmt.Printf("  %d. %s\n", i+1, w)
		}
	}
	return nil
}

func runRuleList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if len(cfg.CustomRules) == 0 {
		fmt.Println("No custom rules defined.")
		fmt.Printf("Add custom rules to: %s\n", config.DefaultConfigPath())
		return nil
	}

	if jsonOutput {
		data, err := json.MarshalIndent(cfg.CustomRules, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling rules: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Println("Custom rules:")
		for i, r := range cfg.CustomRules {
			fmt.Printf("  %d. [%s] %s (%s)\n", i+1, r.Risk, r.Pattern, r.Description)
		}
	}

	return nil
}
