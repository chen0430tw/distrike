package hunter

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// platformDiscoveredRules enumerates Windows-registered cleanup handlers from
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\.
//
// This is the same registry that Windows' built-in SilentCleanup task and
// the user-facing Disk Cleanup (cleanmgr.exe) read. Each subkey is a
// "VolumeCache handler" registered by Windows itself or a third-party
// installer (NVIDIA, Adobe, Visual Studio, etc.).
//
// CRITICAL SAFETY NOTE: the `Folder` value in each handler key is the
// COM IEmptyVolumeCache scan root, NOT a "delete this whole directory"
// instruction. Real handlers (e.g. "Setup Log Files" → Folder=C:\Windows;
// "DownloadsFolder" → Folder=%USERPROFILE%\Downloads) only delete
// specific files matched by their COM logic (mtime > 30 days, specific
// filenames, etc.). Recursively rm-ing the Folder would be catastrophic.
//
// Therefore every rule emitted here is RiskDanger and Action.Hint
// explicitly tells the user to use cleanmgr — we never let distrike's
// own clean pipeline touch these paths automatically.
//
// We additionally skip handlers whose Folder points at obviously
// dangerous roots (drive root, %SystemRoot%, %UserProfile%, etc.) or
// at paths already covered by a built-in distrike rule.
//
// Built-in distrike rules are loaded BEFORE these (see BuiltinRules() in
// rules.go), so on overlap the curated descriptions/actions take
// precedence — these discovered rules only surface gaps where distrike
// doesn't yet have a hand-written rule.
func platformDiscoveredRules() []Rule {
	const volCachesPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches`

	root, err := registry.OpenKey(registry.LOCAL_MACHINE, volCachesPath, registry.READ|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer root.Close()

	subkeys, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	dangerousRoots := buildDangerousRoots()

	var rules []Rule
	for _, name := range subkeys {
		k, err := registry.OpenKey(root, name, registry.READ)
		if err != nil {
			continue
		}

		folderRaw, _, folderErr := k.GetStringValue("Folder")
		var autorun uint32
		if dv, _, err := k.GetIntegerValue("Autorun"); err == nil {
			autorun = uint32(dv)
		}
		k.Close()

		if folderErr != nil || folderRaw == "" {
			// COM-only handlers have no Folder value. They're real
			// cleanup handlers but require the IEmptyVolumeCache COM
			// interface to resolve their target — we cannot represent
			// them as a path-pattern rule.
			continue
		}

		// Folder is sometimes pipe-separated (e.g.
		// "C:\Users\X\AppData\Local\Temp|C:\Windows\Temp|C:\Windows\Logs"),
		// and sometimes contains drive-wildcards like "?:\FOUND.000" which
		// we don't expand. Emit one rule per concrete existing directory.
		seenForHandler := map[string]bool{}
		for _, raw := range strings.Split(folderRaw, "|") {
			raw = strings.TrimSpace(raw)
			if raw == "" || strings.Contains(raw, "?:") {
				continue
			}
			folder := expandEnv(raw)
			if folder == "" {
				continue
			}
			clean := filepath.Clean(folder)
			if seenForHandler[clean] {
				continue
			}
			seenForHandler[clean] = true

			if isDangerousRoot(clean, dangerousRoots) {
				continue
			}
			info, err := os.Stat(clean)
			if err != nil || !info.IsDir() {
				continue
			}

			hint := "Use `cleanmgr /sageset:65535 && cleanmgr /sagerun:65535` (Windows knows which files inside are safe to remove). DO NOT recursively delete this folder directly."
			if autorun >= 1 {
				hint = "Auto-cleaned by Windows SilentCleanup (Autorun=" + autorunString(autorun) + "). " + hint
			}

			rules = append(rules, Rule{
				Pattern:     clean,
				Kind:        inferKind(name, clean),
				Risk:        RiskDanger, // always Danger — Folder is a scan root, not a delete target
				Platform:    "windows",
				Description: "[VolumeCaches] " + name + " — Windows-registered Disk Cleanup handler scan root (NOT a delete-the-whole-folder target)",
				Action: Action{
					Type: "manual",
					Hint: hint,
				},
			})
		}
	}

	return rules
}

// buildDangerousRoots returns absolute paths that must never appear as
// a distrike rule pattern, regardless of what the registry says.
func buildDangerousRoots() map[string]bool {
	m := map[string]bool{}
	add := func(p string) {
		if p == "" {
			return
		}
		m[strings.ToLower(filepath.Clean(p))] = true
	}

	// Drive roots
	for _, l := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		add(string(l) + `:\`)
	}

	// Common system / user roots
	add(os.Getenv("SystemRoot"))
	add(os.Getenv("SystemDrive") + `\`)
	add(os.Getenv("ProgramFiles"))
	add(os.Getenv("ProgramFiles(x86)"))
	add(os.Getenv("ProgramData"))
	add(os.Getenv("UserProfile"))
	add(os.Getenv("Public"))
	add(os.Getenv("AppData"))
	add(os.Getenv("LocalAppData"))

	if up := os.Getenv("UserProfile"); up != "" {
		// Always-present user library folders that should never be a delete target
		for _, sub := range []string{"Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos", "Favorites", "OneDrive", "Contacts"} {
			add(filepath.Join(up, sub))
		}
	}
	return m
}

// isDangerousRoot reports whether path equals one of the protected roots.
// (Subdirectories of these roots are still allowed — only the root itself
// is treated as "never a valid delete target".)
func isDangerousRoot(path string, roots map[string]bool) bool {
	return roots[strings.ToLower(filepath.Clean(path))]
}

// expandEnv resolves Windows environment variables (%SystemRoot%, %LocalAppData%, …)
// in a registry path string.
func expandEnv(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	utf16In, err := windows.UTF16FromString(s)
	if err != nil {
		return s
	}
	// First call with size 0 to get required length.
	n, _ := windows.ExpandEnvironmentStrings(&utf16In[0], nil, 0)
	if n == 0 {
		return s
	}
	buf := make([]uint16, n)
	if _, err := windows.ExpandEnvironmentStrings(&utf16In[0], &buf[0], n); err != nil {
		return s
	}
	return windows.UTF16ToString(buf)
}

// autorunString formats the Autorun DWORD for hint text.
// Windows uses 1 (auto by default), 2 (auto on volume), 3 (high priority);
// any non-zero value means SilentCleanup may touch this handler.
func autorunString(v uint32) string {
	switch v {
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3"
	default:
		return "≥1"
	}
}

// inferKind heuristically maps a VolumeCaches handler name (or its target folder)
// to one of distrike's PreyKind categories.
func inferKind(name, folder string) PreyKind {
	hay := strings.ToLower(name + " " + folder)
	switch {
	case strings.Contains(hay, "recycle"):
		return KindTemp
	case strings.Contains(hay, "temp"):
		return KindTemp
	case strings.Contains(hay, "log"):
		return KindLog
	case strings.Contains(hay, "dump") || strings.Contains(hay, "wer") || strings.Contains(hay, "crash"):
		return KindLog
	case strings.Contains(hay, "download"):
		return KindDownload
	default:
		return KindCache
	}
}
