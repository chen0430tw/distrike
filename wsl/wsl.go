//go:build windows

package wsl

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Distro holds information about a WSL distribution.
type Distro struct {
	Name      string `json:"name"`
	VHDXPath  string `json:"vhdx_path"`
	SizeBytes int64  `json:"size_bytes"`
	Sparse    bool   `json:"sparse"`
	BasePath  string `json:"base_path"`
}

// ListDistros enumerates WSL distributions from the Windows Registry.
func ListDistros() ([]Distro, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Lxss`, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("opening WSL registry key: %w", err)
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("reading WSL subkeys: %w", err)
	}

	var distros []Distro
	for _, guid := range subkeys {
		sub, err := registry.OpenKey(key, guid, registry.READ)
		if err != nil {
			continue
		}
		name, _, _ := sub.GetStringValue("DistributionName")
		basePath, _, _ := sub.GetStringValue("BasePath")
		sub.Close()

		if name == "" || basePath == "" {
			continue
		}

		// Normalize basePath (may have \\?\ prefix)
		basePath = strings.TrimPrefix(basePath, `\\?\`)
		vhdxPath := filepath.Join(basePath, "ext4.vhdx")

		var sizeBytes int64
		if info, err := os.Stat(vhdxPath); err == nil {
			sizeBytes = info.Size()
		}

		distros = append(distros, Distro{
			Name:      name,
			VHDXPath:  vhdxPath,
			SizeBytes: sizeBytes,
			BasePath:  basePath,
		})
	}
	return distros, nil
}

// CompactDistro compacts a WSL distribution's VHDX.
// Returns before and after size in bytes.
func CompactDistro(name string) (before, after int64, err error) {
	// Find distro VHDX
	distros, err := ListDistros()
	if err != nil {
		return 0, 0, err
	}
	var target *Distro
	for i, d := range distros {
		if strings.EqualFold(d.Name, name) {
			target = &distros[i]
			break
		}
	}
	if target == nil {
		return 0, 0, fmt.Errorf("WSL distro %q not found", name)
	}

	before = target.SizeBytes

	// 1. Shutdown WSL
	exec.Command("wsl", "--shutdown").Run()

	// 2. Try fstrim (start WSL briefly)
	exec.Command("wsl", "-d", name, "--", "sudo", "fstrim", "-av").Run()
	exec.Command("wsl", "--shutdown").Run()

	// 3. Compact via diskpart
	script := fmt.Sprintf("select vdisk file=\"%s\"\ncompact vdisk\nexit\n", target.VHDXPath)
	tmpFile := filepath.Join(os.TempDir(), "distrike_compact.txt")
	if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
		return before, before, fmt.Errorf("writing diskpart script: %w", err)
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("diskpart", "/s", tmpFile).CombinedOutput()
	if err != nil {
		return before, before, fmt.Errorf("diskpart: %s\n%w", string(out), err)
	}

	// Measure after
	if info, err := os.Stat(target.VHDXPath); err == nil {
		after = info.Size()
	} else {
		after = before
	}
	return before, after, nil
}

// InternalHunt runs distrike hunt inside a WSL distribution.
func InternalHunt(name string) (string, error) {
	out, err := exec.Command("wsl", "-d", name, "--", "distrike", "hunt", "/", "--json").CombinedOutput()
	if err != nil {
		// distrike might not be installed in WSL
		return "", fmt.Errorf("running distrike in WSL %s: %w\nOutput: %s", name, err, string(out))
	}
	return string(out), nil
}
