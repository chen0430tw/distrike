//go:build !windows

package hunter

// platformDiscoveredRules is a no-op on non-Windows platforms.
//
// On Windows it reads HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
// to discover registered Disk Cleanup handlers (the same source SilentCleanup
// uses). There is no equivalent on Linux/macOS — systemd-tmpfiles and macOS
// periodic scripts use plain config files, not a registry of pluggable handlers,
// so they're already covered by static rules in rules_linux.go / rules_darwin.go.
func platformDiscoveredRules() []Rule {
	return nil
}
