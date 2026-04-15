//go:build windows

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"distrike/internal/units"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/registry"
)

var wslCmd = &cobra.Command{
	Use:   "wsl",
	Short: "WSL distribution space management (Windows only)",
}

var wslListCmd = &cobra.Command{
	Use:   "list",
	Short: "List WSL distributions with VHDX sizes",
	RunE:  runWSLList,
}

var wslCompactCmd = &cobra.Command{
	Use:   "compact [distro]",
	Short: "Compact WSL VHDX (fstrim + diskpart)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runWSLCompact,
}

var wslHuntCmd = &cobra.Command{
	Use:   "hunt [distro]",
	Short: "Hunt prey inside a WSL distribution",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runWSLHunt,
}

func init() {
	wslCmd.AddCommand(wslListCmd, wslCompactCmd, wslHuntCmd)
	wslCompactCmd.Flags().Bool("all", false, "compact all distributions")
	rootCmd.AddCommand(wslCmd)
}

// wslDistro holds information about a single WSL distribution.
type wslDistro struct {
	Name        string `json:"name"`
	GUID        string `json:"guid"`
	BasePath    string `json:"base_path"`
	VHDXPath    string `json:"vhdx_path,omitempty"`
	VHDXSize    int64  `json:"vhdx_size_bytes,omitempty"`
	VHDXHuman   string `json:"vhdx_size_human,omitempty"`
	IsDefault   bool   `json:"is_default"`
}

// wslListOutput is the JSON envelope for wsl list.
type wslListOutput struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          string      `json:"tool"`
	ToolVersion   string      `json:"tool_version"`
	Timestamp     string      `json:"timestamp"`
	Platform      string      `json:"platform"`
	Data          []wslDistro `json:"data"`
}

const lxssKeyPath = `Software\Microsoft\Windows\CurrentVersion\Lxss`

func runWSLList(cmd *cobra.Command, args []string) error {
	distros, err := enumerateWSLDistros()
	if err != nil {
		return fmt.Errorf("enumerating WSL distros: %w", err)
	}

	if jsonOutput {
		out := wslListOutput{
			SchemaVersion: "1.0",
			Tool:          "distrike",
			ToolVersion:   Version,
			Platform:      "windows",
			Data:          distros,
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling output: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	if len(distros) == 0 {
		fmt.Println("No WSL distributions found.")
		return nil
	}

	fmt.Printf("%-30s  %-12s  %-8s  %s\n", "DISTRO", "VHDX SIZE", "DEFAULT", "PATH")
	fmt.Println(strings.Repeat("-", 90))

	for _, d := range distros {
		sizeStr := "-"
		if d.VHDXSize > 0 {
			sizeStr = units.FormatSize(d.VHDXSize)
		}
		def := ""
		if d.IsDefault {
			def = "*"
		}
		fmt.Printf("%-30s  %-12s  %-8s  %s\n", d.Name, sizeStr, def, d.VHDXPath)
	}

	return nil
}

func runWSLCompact(cmd *cobra.Command, args []string) error {
	compactAll, _ := cmd.Flags().GetBool("all")

	distros, err := enumerateWSLDistros()
	if err != nil {
		return fmt.Errorf("enumerating WSL distros: %w", err)
	}

	var targets []wslDistro
	if compactAll {
		targets = distros
	} else if len(args) > 0 {
		name := strings.ToLower(args[0])
		for _, d := range distros {
			if strings.ToLower(d.Name) == name {
				targets = append(targets, d)
				break
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("distro %q not found", args[0])
		}
	} else {
		// Use default distro
		for _, d := range distros {
			if d.IsDefault {
				targets = append(targets, d)
				break
			}
		}
		if len(targets) == 0 && len(distros) > 0 {
			targets = append(targets, distros[0])
		}
	}

	if len(targets) == 0 {
		fmt.Println("No WSL distributions to compact.")
		return nil
	}

	// Step 1: Shutdown WSL
	fmt.Fprintln(cmd.ErrOrStderr(), "Shutting down WSL...")
	shutdownCmd := exec.Command("wsl", "--shutdown")
	shutdownCmd.Stderr = os.Stderr
	if err := shutdownCmd.Run(); err != nil {
		return fmt.Errorf("wsl --shutdown: %w", err)
	}

	for _, d := range targets {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nCompacting %s...\n", d.Name)

		// Step 2: fstrim inside distro
		fmt.Fprintln(cmd.ErrOrStderr(), "  Running fstrim...")
		fstrimCmd := exec.Command("wsl", "-d", d.Name, "--", "sudo", "fstrim", "-av")
		fstrimCmd.Stdout = os.Stderr
		fstrimCmd.Stderr = os.Stderr
		_ = fstrimCmd.Run() // fstrim may fail if not supported, continue anyway

		// Shutdown again after fstrim
		shutdownCmd2 := exec.Command("wsl", "--shutdown")
		_ = shutdownCmd2.Run()

		// Step 3: diskpart compact
		if d.VHDXPath != "" {
			fmt.Fprintln(cmd.ErrOrStderr(), "  Running diskpart compact...")

			// Get size before
			var sizeBefore int64
			if info, err := os.Stat(d.VHDXPath); err == nil {
				sizeBefore = info.Size()
			}

			// Create diskpart script
			script := fmt.Sprintf("select vdisk file=\"%s\"\ncompact vdisk\n", d.VHDXPath)
			tmpFile, err := os.CreateTemp("", "distrike-diskpart-*.txt")
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  Error creating temp file: %v\n", err)
				continue
			}
			tmpFile.WriteString(script)
			tmpFile.Close()

			diskpartCmd := exec.Command("diskpart", "/s", tmpFile.Name())
			diskpartCmd.Stdout = os.Stderr
			diskpartCmd.Stderr = os.Stderr
			if err := diskpartCmd.Run(); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  Diskpart failed (may need Administrator): %v\n", err)
			}
			os.Remove(tmpFile.Name())

			// Show size delta
			if info, err := os.Stat(d.VHDXPath); err == nil {
				sizeAfter := info.Size()
				freed := sizeBefore - sizeAfter
				if freed > 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "  Freed: %s (%s -> %s)\n",
						units.FormatSize(freed),
						units.FormatSize(sizeBefore),
						units.FormatSize(sizeAfter))
				} else {
					fmt.Fprintln(cmd.ErrOrStderr(), "  No significant space recovered.")
				}
			}
		}
	}

	fmt.Println("Compact complete.")
	return nil
}

func runWSLHunt(cmd *cobra.Command, args []string) error {
	distroName := ""
	if len(args) > 0 {
		distroName = args[0]
	}

	// Build wsl command
	wslArgs := []string{}
	if distroName != "" {
		wslArgs = append(wslArgs, "-d", distroName)
	}
	wslArgs = append(wslArgs, "--", "distrike", "hunt", "/", "--json")

	huntCmd := exec.Command("wsl", wslArgs...)
	huntCmd.Stderr = os.Stderr

	output, err := huntCmd.Output()
	if err != nil {
		return fmt.Errorf("running distrike hunt in WSL: %w (is distrike installed in WSL?)", err)
	}

	fmt.Println(string(output))
	return nil
}

// enumerateWSLDistros reads the Windows registry to find WSL distributions.
func enumerateWSLDistros() ([]wslDistro, error) {
	lxssKey, err := registry.OpenKey(registry.CURRENT_USER, lxssKeyPath, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("opening Lxss registry key: %w", err)
	}
	defer lxssKey.Close()

	// Read default distribution GUID
	defaultGUID, _, _ := lxssKey.GetStringValue("DefaultDistribution")

	// Enumerate subkeys (each is a GUID)
	subkeys, err := lxssKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("reading Lxss subkeys: %w", err)
	}

	var distros []wslDistro
	for _, guid := range subkeys {
		subKey, err := registry.OpenKey(registry.CURRENT_USER, lxssKeyPath+`\`+guid, registry.READ)
		if err != nil {
			continue
		}

		name, _, _ := subKey.GetStringValue("DistributionName")
		basePath, _, _ := subKey.GetStringValue("BasePath")
		subKey.Close()

		if name == "" {
			continue
		}

		d := wslDistro{
			Name:      name,
			GUID:      guid,
			BasePath:  basePath,
			IsDefault: strings.EqualFold(guid, defaultGUID),
		}

		// Look for ext4.vhdx
		if basePath != "" {
			vhdxPath := filepath.Join(basePath, "ext4.vhdx")
			if info, err := os.Stat(vhdxPath); err == nil {
				d.VHDXPath = vhdxPath
				d.VHDXSize = info.Size()
				d.VHDXHuman = units.FormatSize(info.Size())
			}
		}

		distros = append(distros, d)
	}

	return distros, nil
}
