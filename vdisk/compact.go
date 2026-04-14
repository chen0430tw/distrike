package vdisk

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CompactVHDX compacts a VHDX file using diskpart.
// Requires Administrator privileges.
// Returns before and after size in bytes.
func CompactVHDX(vhdxPath string) (before, after int64, err error) {
	info, err := os.Stat(vhdxPath)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", vhdxPath, err)
	}
	before = info.Size()

	// Create diskpart script
	script := fmt.Sprintf("select vdisk file=\"%s\"\ncompact vdisk\nexit\n", vhdxPath)
	tmpFile := filepath.Join(os.TempDir(), "distrike_compact_vhdx.txt")
	if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
		return before, before, fmt.Errorf("writing diskpart script: %w", err)
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("diskpart", "/s", tmpFile).CombinedOutput()
	if err != nil {
		return before, before, fmt.Errorf("diskpart failed: %s\n%w", string(out), err)
	}
	if !strings.Contains(string(out), "successfully") {
		return before, before, fmt.Errorf("diskpart may have failed: %s", string(out))
	}

	if info, err := os.Stat(vhdxPath); err == nil {
		after = info.Size()
	} else {
		after = before
	}
	return before, after, nil
}

// CompactVMDK compacts a VMDK file using vmware-vdiskmanager.
// Returns before and after size in bytes.
func CompactVMDK(vmdkPath string) (before, after int64, err error) {
	info, err := os.Stat(vmdkPath)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", vmdkPath, err)
	}
	before = info.Size()

	// Find vmware-vdiskmanager
	mgr := findVDiskManager()
	if mgr == "" {
		return before, before, fmt.Errorf("vmware-vdiskmanager not found; check VMware Workstation installation or PATH")
	}

	out, err := exec.Command(mgr, "-k", vmdkPath).CombinedOutput()
	if err != nil {
		return before, before, fmt.Errorf("vmware-vdiskmanager failed: %s\n%w", string(out), err)
	}

	if info, err := os.Stat(vmdkPath); err == nil {
		after = info.Size()
	} else {
		after = before
	}
	return before, after, nil
}

// CompactVDI compacts a VDI file using VBoxManage.
// Returns before and after size in bytes.
func CompactVDI(vdiPath string) (before, after int64, err error) {
	info, err := os.Stat(vdiPath)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", vdiPath, err)
	}
	before = info.Size()

	vbox := findVBoxManage()
	if vbox == "" {
		return before, before, fmt.Errorf("VBoxManage not found; check VirtualBox installation or PATH")
	}

	out, err := exec.Command(vbox, "modifymedium", "disk", vdiPath, "--compact").CombinedOutput()
	if err != nil {
		return before, before, fmt.Errorf("VBoxManage failed: %s\n%w", string(out), err)
	}

	if info, err := os.Stat(vdiPath); err == nil {
		after = info.Size()
	} else {
		after = before
	}
	return before, after, nil
}

// findVDiskManager searches for vmware-vdiskmanager in common locations.
func findVDiskManager() string {
	// Check PATH first
	if p, err := exec.LookPath("vmware-vdiskmanager"); err == nil {
		return p
	}
	if p, err := exec.LookPath("vmware-vdiskmanager.exe"); err == nil {
		return p
	}

	// Common Windows locations
	candidates := []string{
		`C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe`,
		`C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// findVBoxManage searches for VBoxManage in common locations.
func findVBoxManage() string {
	if p, err := exec.LookPath("VBoxManage"); err == nil {
		return p
	}
	if p, err := exec.LookPath("VBoxManage.exe"); err == nil {
		return p
	}
	candidates := []string{
		`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`,
		`C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
