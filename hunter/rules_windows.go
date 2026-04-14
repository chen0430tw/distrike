// go:build windows

package hunter

func platformSpecificRules() []Rule {
	return []Rule{
		// Temp
		{Pattern: "*/AppData/Local/Temp", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Windows user temp files",
			Action:      Action{Type: "manual", Hint: "Delete temp file contents"}},
		{Pattern: "*/Windows/Temp", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Windows system temp files",
			Action:      Action{Type: "manual", Hint: "Requires Administrator"}},
		{Pattern: "*/$RECYCLE.BIN", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Recycle Bin",
			Action:      Action{Type: "manual", Hint: "Empty Recycle Bin"}},
		{Pattern: "*/AppData/Local/CrashDumps", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Crash dump files",
			Action:      Action{Type: "manual", Hint: "Delete crash dumps"}},
		{Pattern: "*/AppData/Local/D3DSCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "DirectX shader cache",
			Action:      Action{Type: "manual", Hint: "Delete shader cache"}},

		// Virtual disks
		{Pattern: "*.vhdx", Kind: KindVDisk, Risk: RiskCaution, Platform: "windows",
			Description: "Virtual hard disk (WSL/Docker/Hyper-V)",
			Action:      Action{Type: "manual", Hint: "fstrim + diskpart compact vdisk"}},
		{Pattern: "*.vmdk", Kind: KindVDisk, Risk: RiskCaution, Platform: "windows",
			Description: "VMware/LDPlayer virtual disk",
			Action:      Action{Type: "manual", Hint: "vmware-vdiskmanager -k"}},

		// Backups
		{Pattern: "*/MobileSync/Backup", Kind: KindBackup, Risk: RiskDanger, Platform: "windows",
			Description: "iPhone/iPad backup",
			Action:      Action{Type: "manual", Hint: "Verify backups are current before deleting"}},
		{Pattern: "*/WindowsImageBackup", Kind: KindBackup, Risk: RiskDanger, Platform: "windows",
			Description: "Windows system image backup",
			Action:      Action{Type: "manual", Hint: "Only delete if newer backup exists"}},

		// Downloads
		{Pattern: "*/BaiduNetdiskDownload", Kind: KindDownload, Risk: RiskCaution, Platform: "windows",
			Description: "Baidu Netdisk downloads",
			Action:      Action{Type: "manual", Hint: "Check if files are still needed"}},

		// Cygwin
		{Pattern: "*/cygwin64/var/cache/setup", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Cygwin package cache",
			Action:      Action{Type: "manual", Hint: "Delete setup cache contents"}},
	}
}
