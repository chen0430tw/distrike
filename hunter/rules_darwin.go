// go:build darwin

package hunter

func platformSpecificRules() []Rule {
	return []Rule{
		// Xcode
		{Pattern: "*/Library/Developer/Xcode/DerivedData", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Xcode build cache (often 80-200+ GB)",
			Action:      Action{Type: "command", Command: "rm -rf ~/Library/Developer/Xcode/DerivedData/*"}},
		{Pattern: "*/Library/Developer/Xcode/iOS DeviceSupport", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "iOS device support files (~2.5 GB per version)",
			Action:      Action{Type: "manual", Hint: "Delete old iOS versions, Xcode re-downloads on demand"}},

		// Homebrew
		{Pattern: "*/Library/Caches/Homebrew", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Homebrew download cache",
			Action:      Action{Type: "command", Command: "brew cleanup --prune=all"}},

		// Simulators
		{Pattern: "*/Library/Developer/CoreSimulator", Kind: KindCache, Risk: RiskCaution, Platform: "darwin",
			Description: "iOS/watchOS/tvOS simulator runtimes",
			Action:      Action{Type: "command", Command: "xcrun simctl delete unavailable"}},

		// iPhone backup
		{Pattern: "*/Library/Application Support/MobileSync/Backup", Kind: KindBackup, Risk: RiskDanger, Platform: "darwin",
			Description: "iPhone/iPad backup",
			Action:      Action{Type: "manual", Hint: "Verify backups are current before deleting"}},

		// General caches
		{Pattern: "*/Library/Caches", Kind: KindCache, Risk: RiskCaution, Platform: "darwin",
			Description: "Application caches",
			Action:      Action{Type: "manual", Hint: "Selectively delete per-app cache folders"}},

		// Browser caches
		{Pattern: "*/Google/Chrome/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Google Chrome cache",
			Action:      Action{Type: "manual", Hint: "Delete cache or chrome://settings/clearBrowserData"}},
		{Pattern: "*/Google/Chrome/Default/Service Worker/CacheStorage", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Chrome Service Worker cache",
			Action:      Action{Type: "manual", Hint: "Delete cache storage"}},
		{Pattern: "*/Firefox/Profiles/*/cache2", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Firefox disk cache",
			Action:      Action{Type: "manual", Hint: "Delete cache2 contents"}},

		// Electron apps
		{Pattern: "*/discord/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Discord cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Slack/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Slack cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Code/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "VS Code cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/Code/CachedData", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "VS Code cached data",
			Action:      Action{Type: "manual", Hint: "Delete cached data"}},
		{Pattern: "*/GPUCache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "GPU shader cache (Electron/Chromium)",
			Action:      Action{Type: "manual", Hint: "Delete GPU cache"}},

		// Docker
		{Pattern: "*/Docker/Data/vms/0/data/Docker.raw", Kind: KindVDisk, Risk: RiskCaution, Platform: "darwin",
			Description: "Docker Desktop disk image",
			Action:      Action{Type: "command", Command: "docker system prune -af"}},

		// Adobe
		{Pattern: "*/Adobe/Common/Media Cache Files", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Adobe Media Cache",
			Action:      Action{Type: "manual", Hint: "Purge from Premiere Pro preferences"}},

		// Python
		{Pattern: "*/__pycache__", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Python bytecode cache",
			Action:      Action{Type: "manual", Hint: "Delete __pycache__ directories"}},

		// Spotify
		{Pattern: "*/Spotify/PersistentCache", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "Spotify offline cache",
			Action:      Action{Type: "manual", Hint: "Clear in Spotify settings"}},

		// CocoaPods
		{Pattern: "*/Library/Caches/CocoaPods", Kind: KindCache, Risk: RiskSafe, Platform: "darwin",
			Description: "CocoaPods spec and download cache",
			Action:      Action{Type: "command", Command: "pod cache clean --all"}},
	}
}
