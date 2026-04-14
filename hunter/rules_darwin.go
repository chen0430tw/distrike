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
	}
}
