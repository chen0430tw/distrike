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

		// --- Browser caches ---
		{Pattern: "*/Google/Chrome/User Data/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Google Chrome cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents or chrome://settings/clearBrowserData"}},
		{Pattern: "*/Google/Chrome/User Data/Default/Code Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Chrome code/JS cache",
			Action:      Action{Type: "manual", Hint: "Delete code cache contents"}},
		{Pattern: "*/Google/Chrome/User Data/Default/Service Worker/CacheStorage", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Chrome Service Worker cache",
			Action:      Action{Type: "manual", Hint: "Delete cache storage contents"}},
		{Pattern: "*/Microsoft/Edge/User Data/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Microsoft Edge cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents or edge://settings/clearBrowserData"}},
		{Pattern: "*/Microsoft/Edge/User Data/Default/Code Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Edge code/JS cache",
			Action:      Action{Type: "manual", Hint: "Delete code cache contents"}},
		{Pattern: "*/Mozilla/Firefox/Profiles/*/cache2", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Firefox disk cache",
			Action:      Action{Type: "manual", Hint: "Delete cache2 contents"}},

		// --- Electron app caches (Discord, Slack, Teams, etc.) ---
		{Pattern: "*/discord/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Discord cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/discord/Code Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Discord code cache",
			Action:      Action{Type: "manual", Hint: "Delete code cache contents"}},
		{Pattern: "*/Slack/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Slack cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Slack/Service Worker/CacheStorage", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Slack Service Worker cache",
			Action:      Action{Type: "manual", Hint: "Delete cache storage contents"}},
		{Pattern: "*/Microsoft/Teams/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Microsoft Teams cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Code/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "VS Code cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Code/CachedData", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "VS Code cached data",
			Action:      Action{Type: "manual", Hint: "Delete cached data"}},
		{Pattern: "*/Code/CachedExtensions", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "VS Code cached extensions",
			Action:      Action{Type: "manual", Hint: "Delete cached extensions"}},
		{Pattern: "*/GPUCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "GPU shader cache (Electron/Chromium)",
			Action:      Action{Type: "manual", Hint: "Delete GPU cache contents"}},

		// --- IDE caches ---
		{Pattern: "*/JetBrains/*/caches", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "JetBrains IDE caches (IntelliJ/PyCharm/GoLand/etc.)",
			Action:      Action{Type: "manual", Hint: "Delete caches directory contents"}},
		{Pattern: "*/JetBrains/*/index", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "JetBrains IDE index",
			Action:      Action{Type: "manual", Hint: "Delete index directory, IDE will rebuild"}},
		{Pattern: "*/JetBrains/*/log", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "JetBrains IDE logs",
			Action:      Action{Type: "manual", Hint: "Delete log contents"}},

		// --- Adobe ---
		{Pattern: "*/Adobe/Common/Media Cache Files", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Adobe Media Cache",
			Action:      Action{Type: "manual", Hint: "Delete media cache or purge from Premiere Pro preferences"}},
		{Pattern: "*/Adobe/Common/Media Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Adobe Media Cache database",
			Action:      Action{Type: "manual", Hint: "Purge from Premiere Pro > Preferences > Media Cache"}},

		// --- Windows Update ---
		{Pattern: "*/SoftwareDistribution/Download", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Update download cache",
			Action:      Action{Type: "command", Command: "sudo powershell Stop-Service wuauserv; Remove-Item C:\\Windows\\SoftwareDistribution\\Download\\* -Recurse -Force; Start-Service wuauserv"}},

		// --- Game platforms ---
		{Pattern: "*/Steam/steamapps/shadercache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Steam shader cache",
			Action:      Action{Type: "manual", Hint: "Delete shader cache, Steam will rebuild"}},
		{Pattern: "*/EpicGamesLauncher/Saved/webcache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Epic Games Launcher web cache",
			Action:      Action{Type: "manual", Hint: "Delete webcache contents"}},
		{Pattern: "*/EpicGamesLauncher/Saved/VaultCache", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "Epic Games Vault cache (downloaded assets)",
			Action:      Action{Type: "manual", Hint: "Check if assets are still needed"}},

		// --- Python ---
		{Pattern: "*/__pycache__", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Python bytecode cache",
			Action:      Action{Type: "manual", Hint: "Delete __pycache__ directories"}},
		{Pattern: "*/.mypy_cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "mypy type checker cache",
			Action:      Action{Type: "manual", Hint: "Delete .mypy_cache"}},
		{Pattern: "*/.pytest_cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "pytest cache",
			Action:      Action{Type: "manual", Hint: "Delete .pytest_cache"}},

		// --- Git large repos ---
		{Pattern: "*/.git/objects", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "Git object store (may contain large history)",
			Action:      Action{Type: "command", Command: "git gc --aggressive --prune=now"}},

		// --- Misc app data ---
		{Pattern: "*/Spotify/Data", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Spotify offline cache",
			Action:      Action{Type: "manual", Hint: "Clear cache in Spotify settings"}},
		{Pattern: "*/LINE/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "LINE messenger cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Telegram Desktop/tdata/user_data/cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Telegram cache",
			Action:      Action{Type: "manual", Hint: "Clear in Telegram settings > Data and Storage"}},

		// --- Windows system cleanable ---
		{Pattern: "*/Windows/Prefetch", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Prefetch (app launch optimization cache)",
			Action:      Action{Type: "manual", Hint: "Delete contents, Windows will rebuild"}},
		{Pattern: "*/Windows/SoftwareDistribution/Download", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Update download cache",
			Action:      Action{Type: "manual", Hint: "Stop wuauserv, delete contents, restart wuauserv"}},
	}
}
