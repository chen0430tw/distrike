// go:build windows

package hunter

func platformSpecificRules() []Rule {
	return []Rule{
		// --- Temp ---
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
		{Pattern: "*/SoftwareDistribution/DeliveryOptimization", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Update Delivery Optimization cache (P2P update chunks)",
			Action:      Action{Type: "command", Command: "sudo powershell Delete-DeliveryOptimizationCache -Force"}},
		// DataStore contains update history/metadata — safe to clear, resets Windows Update history display
		{Pattern: "*/SoftwareDistribution/DataStore", Kind: KindLog, Risk: RiskCaution, Platform: "windows",
			Description: "Windows Update history database — clearing resets update history display but does not affect installed updates",
			Action:      Action{Type: "command", Command: "sudo powershell Stop-Service wuauserv; Remove-Item C:\\Windows\\SoftwareDistribution\\DataStore\\* -Recurse -Force; Start-Service wuauserv"}},

		// --- Live Kernel Reports (large kernel dump files, often GBs) ---
		{Pattern: "*/Windows/LiveKernelReports", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Live Kernel Report dumps (.dmp) generated by driver/hardware errors",
			Action:      Action{Type: "manual", Hint: "Note any recurring errors before deleting — requires Administrator"}},

		// --- INetCache — WinINet / WebView2 / IE cache ---
		{Pattern: "*/Microsoft/Windows/INetCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "WinINet cache — used by Internet Explorer, WebView2, and some desktop apps",
			Action:      Action{Type: "manual", Hint: "Delete contents — safe to remove, apps re-download as needed"}},

		// --- RDP (Remote Desktop) bitmap cache ---
		{Pattern: "*/Microsoft/Terminal Server Client/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Remote Desktop (RDP) bitmap cache — graphical data from past RDP sessions",
			Action:      Action{Type: "manual", Hint: "Safe to delete — RDP rebuilds cache on next connection"}},

		// --- NuGet package cache (.NET) ---
		{Pattern: "*/NuGet/v3-cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NuGet v3 HTTP cache (downloaded package metadata and files)",
			Action:      Action{Type: "command", Command: "dotnet nuget locals http-cache --clear"}},
		{Pattern: "*/.nuget/packages", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NuGet global packages cache (~/.nuget/packages) — restored on next build",
			Action:      Action{Type: "command", Command: "dotnet nuget locals global-packages --clear"}},

		// --- WiX / .NET installer source cache (DANGER: breaks uninstall) ---
		{Pattern: "*/ProgramData/Package Cache", Kind: KindCache, Risk: RiskDanger, Platform: "windows",
			Description: "WiX/Visual Studio installer source cache — DANGER: deleting prevents uninstalling or modifying affected apps",
			Action:      Action{Type: "manual", Hint: "Only remove entries for apps you have already uninstalled — use Revo Uninstaller or check before deleting"}},

		// --- Music streaming caches (国内) ---
		{Pattern: "*/AppData/Roaming/KuGou/Temp", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Kugou Music temp/streaming cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — Kugou re-buffers on next play"}},
		{Pattern: "*/AppData/Roaming/KuGou/DownloadSongDefaultPath", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "Kugou Music downloaded songs cache",
			Action:      Action{Type: "manual", Hint: "Check if you still want these downloads"}},
		{Pattern: "*/AppData/Roaming/kuwo", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Kuwo Music temp cache",
			Action:      Action{Type: "manual", Hint: "Delete temp contents — Kuwo re-buffers on next play"}},
		{Pattern: "*/AppData/Local/NetEase/CloudMusic/webdata", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NetEase Cloud Music web cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — CloudMusic rebuilds on next launch"}},

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

		// --- Clipboard / utility ---
		{Pattern: "*/Ditto/Ditto.db", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "Ditto clipboard history database",
			Action:      Action{Type: "manual", Hint: "Purge old entries in Ditto settings or delete Ditto.db"}},

		// --- Claude Code old versions ---
		{Pattern: "*/.local/share/claude/versions", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Claude Code old version binaries",
			Action:      Action{Type: "manual", Hint: "Keep latest version, delete older ones"}},

		// --- WebEx ---
		{Pattern: "*/WebEx", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "WebEx meeting cache and temp files",
			Action:      Action{Type: "manual", Hint: "Delete if not actively using WebEx"}},

		// --- Windows system cleanable ---
		{Pattern: "*/Windows/Prefetch", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Prefetch (app launch optimization cache)",
			Action:      Action{Type: "manual", Hint: "Delete contents, Windows will rebuild"}},
		{Pattern: "*/Windows/SoftwareDistribution/Download", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Update download cache",
			Action:      Action{Type: "manual", Hint: "Stop wuauserv, delete contents, restart wuauserv"}},

		// --- Thumbnail & Icon cache (火绒/CCleaner core item) ---
		// Cosmetic: Windows regenerates thumbcache automatically on next folder browse.
		// Only frees space from orphaned thumbnails of already-deleted files.
		{Pattern: "*/Microsoft/Windows/Explorer", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Cosmetic:    true,
			Description: "Windows thumbnail & icon cache — regenerates on next folder browse, only frees orphaned entries",
			Action:      Action{Type: "command", Command: "sudo powershell Stop-Process -Name explorer -Force; Remove-Item $env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*.db,$env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\iconcache_*.db -Force; Start-Process explorer"}},

		// --- Font cache ---
		// Cosmetic: FontCache service rebuilds this automatically within seconds of deletion.
		{Pattern: "*/Microsoft/Windows/FontCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Cosmetic:    true,
			Description: "Windows font cache — FontCache service rebuilds automatically, negligible real-world impact",
			Action:      Action{Type: "command", Command: "sudo powershell Stop-Service FontCache; Remove-Item $env:LOCALAPPDATA\\Microsoft\\Windows\\FontCache\\* -Recurse -Force; Start-Service FontCache"}},

		// --- Windows Error Reporting ---
		{Pattern: "*/Microsoft/Windows/WER/ReportArchive", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Error Reporting archived crash reports",
			Action:      Action{Type: "manual", Hint: "Delete contents — archived after upload to Microsoft"}},
		{Pattern: "*/Microsoft/Windows/WER/ReportQueue", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Error Reporting pending crash reports (not yet uploaded)",
			Action:      Action{Type: "manual", Hint: "Delete contents if you don't need crash diagnostics"}},
		{Pattern: "*/ProgramData/Microsoft/Windows/WER/ReportArchive", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "Windows Error Reporting system-wide archived crash reports",
			Action:      Action{Type: "manual", Hint: "Delete contents — requires Administrator"}},

		// --- Memory dumps ---
		{Pattern: "*/Windows/Minidump", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Windows BSOD minidump files",
			Action:      Action{Type: "manual", Hint: "Note the Stop code first, then safe to delete"}},
		{Pattern: "*/Windows/MEMORY.DMP", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "Windows full/kernel memory dump (~RAM size)",
			Action:      Action{Type: "manual", Hint: "Note the Stop code first, then safe to delete — requires Administrator"}},

		// --- Chkdsk recovered fragments ---
		// Cosmetic: typically KB-sized, only present after a disk error event.
		{Pattern: "*.chk", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Cosmetic:    true,
			Description: "Chkdsk recovered file fragments — typically KB-sized, only appear after disk errors",
			Action:      Action{Type: "manual", Hint: "Safe to delete — recovered fragments from disk errors, rarely recoverable"}},

		// --- Windows.old (previous OS installation) ---
		{Pattern: "*/Windows.old", Kind: KindTemp, Risk: RiskDanger, Platform: "windows",
			Description: "Previous Windows installation — safe to delete if upgrade is stable (often 15–30 GB)",
			Action:      Action{Type: "command", Command: "cleanmgr /d C: /sageset:65535 && cleanmgr /d C: /sagerun:65535"}},

		// --- Windows Spotlight lock screen cache ---
		// Cosmetic: typically <100 MB, Windows re-downloads automatically in the background.
		{Pattern: "*/ContentDeliveryManager_cw5n1h2txyewy/LocalState/Assets", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Cosmetic:    true,
			Description: "Windows Spotlight lock screen cache — typically <100 MB, re-downloaded automatically",
			Action:      Action{Type: "manual", Hint: "Delete contents — Windows will re-download lock screen images"}},

		// --- Event logs (CCleaner Advanced) ---
		{Pattern: "*/System32/winevt/Logs", Kind: KindLog, Risk: RiskCaution, Platform: "windows",
			Description: "Windows Event Viewer logs (*.evtx) — requires Administrator",
			Action:      Action{Type: "command", Command: "sudo powershell Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | ForEach-Object { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }"}},

		// --- GPU driver shader caches ---
		{Pattern: "*/NVIDIA/DXCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NVIDIA DirectX shader cache (rebuilt by driver on next use)",
			Action:      Action{Type: "manual", Hint: "Delete contents — GPU driver rebuilds automatically"}},
		{Pattern: "*/NVIDIA/GLCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NVIDIA OpenGL shader cache (rebuilt by driver on next use)",
			Action:      Action{Type: "manual", Hint: "Delete contents — GPU driver rebuilds automatically"}},
		{Pattern: "*/NVIDIA/ComputeCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "NVIDIA CUDA compute cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — rebuilt on next CUDA workload"}},
		{Pattern: "*/AMD/DxCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "AMD DirectX shader cache (rebuilt by driver on next use)",
			Action:      Action{Type: "manual", Hint: "Delete contents — GPU driver rebuilds automatically"}},
		{Pattern: "*/AMD/GLCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "AMD OpenGL shader cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — GPU driver rebuilds automatically"}},

		// --- Java Web Start cache ---
		{Pattern: "*/Sun/Java/Deployment/cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Java Web Start application cache",
			Action:      Action{Type: "command", Command: "javaws -uninstall"}},

		// --- Microsoft Office cache ---
		{Pattern: "*/Microsoft/Office/16.0/OfficeFileCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Office 2016/365 file sync cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — rebuilds on next Office sync"}},
		{Pattern: "*/Microsoft/Office/15.0/OfficeFileCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Office 2013 file sync cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — rebuilds on next Office sync"}},

		// --- Visual Studio ---
		{Pattern: "*/.vs", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Visual Studio solution cache (.vs folder — IntelliSense, breakpoints, layout)",
			Action:      Action{Type: "manual", Hint: "Delete .vs folder — VS recreates when solution reopened (loses breakpoints/layout)"}},
		{Pattern: "*/VisualStudio/*/ComponentModelCache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Visual Studio extension component model cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — VS rebuilds on next start (may be slow)"}},
		{Pattern: "*/VisualStudio/*/ActivityLog.xml", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "Visual Studio activity log",
			Action:      Action{Type: "manual", Hint: "Delete file — VS creates a new one on next start"}},

		// --- Zoom ---
		{Pattern: "*/AppData/Roaming/Zoom/logs", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "Zoom meeting and application logs",
			Action:      Action{Type: "manual", Hint: "Delete log files"}},
		{Pattern: "*/AppData/Roaming/Zoom/data/Plugins", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "Zoom plugin cache",
			Action:      Action{Type: "manual", Hint: "Delete contents — Zoom re-downloads on next start"}},

		// --- WeChat cache ---
		{Pattern: "*/WeChat Files/*/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "WeChat render cache",
			Action:      Action{Type: "manual", Hint: "Delete Cache folder contents — WeChat re-downloads as needed"}},
		{Pattern: "*/WeChat Files/*/Temp", Kind: KindTemp, Risk: RiskSafe, Platform: "windows",
			Description: "WeChat temp files",
			Action:      Action{Type: "manual", Hint: "Delete Temp folder contents"}},
		// WeChat image cache — auto-saved thumbnails/previews, distinct from FileStorage (user-saved files)
		{Pattern: "*/WeChat Files/*/Image", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "WeChat auto-cached chat images (distinct from FileStorage — re-downloadable)",
			Action:      Action{Type: "manual", Hint: "Delete folder — WeChat re-downloads image previews on demand. FileStorage (user-saved files) is not touched."}},
		{Pattern: "*/WeChat Files/*/Video", Kind: KindCache, Risk: RiskCaution, Platform: "windows",
			Description: "WeChat auto-cached chat videos",
			Action:      Action{Type: "manual", Hint: "Delete folder — WeChat re-downloads video thumbnails/previews on demand"}},

		// --- QQ / QQNT cache ---
		// IMPORTANT: QQ does NOT long-retain server-side media. Roaming window is
		// 7d (free) / 30d (VIP) / 2y (SVIP). Beyond that, the local file under
		// nt_qq/nt_data/Pic|Video IS the canonical copy — deletion is permanent.
		// Tencent's own built-in cleaner (设置 → 存储管理 → 清理缓存) is conservative
		// and only touches "render cache" type folders, never nt_data/Pic|Video.

		{Pattern: "*/Tencent Files/*/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "QQ render cache (legacy QQ, pre-NT)",
			Action:      Action{Type: "manual", Hint: "Delete Cache folder contents"}},
		{Pattern: "*/Tencent/QQNT/*/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "QQNT (new QQ) app cache",
			Action:      Action{Type: "manual", Hint: "Delete Cache folder contents"}},

		// QQNT received media — DO NOT TREAT AS DISPOSABLE CACHE.
		// Tencent expires server-side originals after the roaming window above,
		// after which these local files are the only copy.
		{Pattern: "*/nt_qq/nt_data/Pic", Kind: KindCache, Risk: RiskDanger, Platform: "windows",
			Description: "QQNT local image store — Tencent only keeps server originals during the roaming window (7d free / 30d VIP / 2y SVIP). Older images are unrecoverable once deleted.",
			Action:      Action{Type: "manual", Hint: "Save important images first. Use QQ's built-in 设置→存储管理 for safer partial cleanup."}},
		{Pattern: "*/nt_qq/nt_data/Video", Kind: KindCache, Risk: RiskDanger, Platform: "windows",
			Description: "QQNT local video store — same retention as Pic; deletion of older videos is permanent.",
			Action:      Action{Type: "manual", Hint: "Save important videos first. Use QQ's built-in 设置→存储管理 for safer partial cleanup."}},
		{Pattern: "*/nt_qq/nt_data/Emoji", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "QQNT emoji cache (system + market emoji — re-downloadable from emoji catalog)",
			Action:      Action{Type: "manual", Hint: "Safe to delete — QQ re-downloads emoji on next use"}},

		// QQNT 9.x relocated some caches to AppData\Local\TencentQQ\<id>\<media>.
		// Same retention semantics as nt_qq/nt_data — RiskDanger for image/video.
		{Pattern: "*/AppData/Local/TencentQQ/*/Image", Kind: KindCache, Risk: RiskDanger, Platform: "windows",
			Description: "QQNT 9.x local image store (new path) — same Tencent retention rules as nt_qq/nt_data/Pic",
			Action:      Action{Type: "manual", Hint: "Save important images first."}},
		{Pattern: "*/AppData/Local/TencentQQ/*/Video", Kind: KindCache, Risk: RiskDanger, Platform: "windows",
			Description: "QQNT 9.x local video store (new path) — same retention as Pic",
			Action:      Action{Type: "manual", Hint: "Save important videos first."}},
		{Pattern: "*/AppData/Local/TencentQQ/*/web", Kind: KindCache, Risk: RiskSafe, Platform: "windows",
			Description: "QQNT 9.x web cache (chromium subprocess cache)",
			Action:      Action{Type: "manual", Hint: "Safe to delete — re-fetched by embedded browser as needed"}},

		// --- OBS Studio ---
		{Pattern: "*/obs-studio/logs", Kind: KindLog, Risk: RiskSafe, Platform: "windows",
			Description: "OBS Studio recording and streaming logs",
			Action:      Action{Type: "manual", Hint: "Delete old log files — keep recent ones for troubleshooting"}},

		// --- Steam partially downloaded games ---
		{Pattern: "*/Steam/steamapps/downloading", Kind: KindTemp, Risk: RiskCaution, Platform: "windows",
			Description: "Steam in-progress game downloads (incomplete, not playable)",
			Action:      Action{Type: "manual", Hint: "Only delete if you no longer want these downloads — Steam will restart from scratch"}},

		// --- Notepad++ auto-save backups ---
		{Pattern: "*/notepad++/backup", Kind: KindTemp, Risk: RiskCaution, Platform: "windows",
			Description: "Notepad++ auto-saved backup files",
			Action:      Action{Type: "manual", Hint: "Check for unsaved work before deleting"}},
	}
}
