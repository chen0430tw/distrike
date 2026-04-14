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
	}
}
