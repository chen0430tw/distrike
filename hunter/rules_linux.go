// go:build linux

package hunter

func platformSpecificRules() []Rule {
	return []Rule{
		// APT
		{Pattern: "/var/cache/apt", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "APT package cache",
			Action:      Action{Type: "command", Command: "sudo apt clean", Shell: "bash"}},

		// Journal logs
		{Pattern: "/var/log", Kind: KindLog, Risk: RiskSafe, Platform: "linux",
			Description: "System logs (journalctl)",
			Action:      Action{Type: "command", Command: "sudo journalctl --vacuum-time=7d", Shell: "bash"}},

		// Snap
		{Pattern: "/var/lib/snapd", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Snap package data",
			Action:      Action{Type: "manual", Hint: "sudo snap remove --purge <unused-snap>"}},

		// Rotated logs
		{Pattern: "/var/log/*.gz", Kind: KindLog, Risk: RiskSafe, Platform: "linux",
			Description: "Compressed rotated log files",
			Action:      Action{Type: "command", Command: "sudo find /var/log -name '*.gz' -delete", Shell: "bash"}},

		// Orphan packages
		{Pattern: "__runtime_detect__orphan_packages", Kind: KindOrphan, Risk: RiskSafe, Platform: "linux",
			Description: "Orphaned packages",
			Action:      Action{Type: "command", Command: "sudo apt autoremove -y", Shell: "bash"}},

		// Browser caches
		{Pattern: "*/.cache/google-chrome/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Google Chrome cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.cache/chromium/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Chromium cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.mozilla/firefox/*/cache2", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Firefox disk cache",
			Action:      Action{Type: "manual", Hint: "Delete cache2 contents"}},

		// Electron apps
		{Pattern: "*/.config/discord/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Discord cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.config/Code/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "VS Code cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.config/Code/CachedData", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "VS Code cached data",
			Action:      Action{Type: "manual", Hint: "Delete cached data"}},

		// Docker
		{Pattern: "/var/lib/docker/overlay2", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Docker image layers",
			Action:      Action{Type: "command", Command: "docker system prune -af", Shell: "bash"}},

		// Flatpak
		{Pattern: "/var/tmp/flatpak-cache*", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Flatpak temporary cache",
			Action:      Action{Type: "manual", Hint: "Delete flatpak cache"}},

		// Python
		{Pattern: "*/__pycache__", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Python bytecode cache",
			Action:      Action{Type: "manual", Hint: "find . -type d -name __pycache__ -exec rm -rf {} +"}},

		// Trash
		{Pattern: "*/.local/share/Trash", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "User trash (deleted files)",
			Action:      Action{Type: "manual", Hint: "Empty trash"}},

		// Thumbnails
		{Pattern: "*/.cache/thumbnails", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Image thumbnail cache",
			Action:      Action{Type: "manual", Hint: "Delete thumbnails, will regenerate"}},

		// Core dumps
		{Pattern: "/var/crash", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "Crash reports",
			Action:      Action{Type: "command", Command: "sudo rm -f /var/crash/*", Shell: "bash"}},
	}
}
