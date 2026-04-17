package hunter

// AppDiscover implements MSCM-inspired (Multi-Source Semantic Collapse Model)
// app directory discovery for non-standard install locations.
//
// Problem: rules use glob patterns like "*/Google/Chrome/User Data/Default/Cache".
// These miss Chrome installed at D:\软件\Chrome\ (no "Google" parent directory).
//
// MSCM adaptation:
//
//	Five signal layers per candidate directory:
//	  1. name_match   — dir name fuzzy-matches known app name tokens
//	  2. marker_exe   — directory contains a known marker executable
//	  3. marker_dir   — directory contains a known internal subdirectory
//	  4. size_tier    — directory size ≥ minimum expected for this app
//	  5. prey_exists  — the target cleanup subdir actually exists on disk
//
//	Gate (Fuzzy Symmetric Gate, mirrored from MSCM):
//	  quality = sqrt(cross_layer_ratio × signal_diversity)
//	  gate    = 1 + α × tanh(β × (quality − neutral))
//	  total   = linear_score × gate
//
//	Threshold: total > 0.55 → confirmed, synthesize Prey directly.
//
// This produces prey entries independently of the glob-pattern rule system,
// so no existing rules need modification.

import (
	"math"
	"os"
	"path/filepath"
	"strings"
)

// ─── Signal layers ────────────────────────────────────────────────────────────

const (
	layerNameMatch  = "name_match"
	layerMarkerExe  = "marker_exe"
	layerMarkerDir  = "marker_dir"
	layerSizeTier   = "size_tier"
	layerPreyExists = "prey_exists"
)

type appSignal struct {
	layer string
	score float64
}

// ─── Gate constants (from MSCM) ───────────────────────────────────────────────

const (
	gateAlpha   = 0.6
	gateNeutral = 0.5
	gateBeta    = 3.0
)

func mscmGate(signals []appSignal) float64 {
	if len(signals) == 0 {
		return 0
	}

	// Linear score (average of signal scores, normalised to [0,1])
	var sum float64
	for _, s := range signals {
		sum += s.score
	}
	linear := sum / 5.0 // 5 = total possible layers

	// Cross-layer coverage: how many distinct layers fired / 5
	layers := make(map[string]struct{}, len(signals))
	for _, s := range signals {
		layers[s.layer] = struct{}{}
	}
	crossRatio := float64(len(layers)) / 5.0

	// Diversity: distinct signal texts / total signals
	diversity := float64(len(layers)) / float64(len(signals))

	// Quality = geometric mean (mirrors MSCM)
	quality := math.Sqrt(crossRatio * diversity)

	// Fuzzy symmetric gate
	gate := 1.0 + gateAlpha*math.Tanh(gateBeta*(quality-gateNeutral))

	return linear * gate
}

// ─── PreyLocation: relative path to clean within app root ────────────────────

type preyLocation struct {
	relPath string   // path relative to app root, using forward slashes
	kind    PreyKind
	risk    Risk
	desc    string
	hint    string
}

// ─── App fingerprint ─────────────────────────────────────────────────────────

type appFingerprint struct {
	displayName string
	nameTokens  []string // lowercase tokens to fuzzy-match against dir name
	markerExes  []string // exe files that confirm identity (case-insensitive)
	markerDirs  []string // immediate subdirs that confirm identity (case-insensitive)
	minSizeBytes int64   // minimum expected size; below this → size_tier score 0
	preyLocations []preyLocation
}

// ─── Fingerprint database ─────────────────────────────────────────────────────

var knownApps = []appFingerprint{
	{
		displayName:  "Google Chrome",
		nameTokens:   []string{"chrome", "chromium", "googlechrome"},
		markerExes:   []string{"chrome.exe", "chromium.exe"},
		markerDirs:   []string{"user data"},
		minSizeBytes: 50 << 20, // 50 MB
		preyLocations: []preyLocation{
			{relPath: "User Data/Default/Cache", kind: KindCache, risk: RiskSafe,
				desc: "Chrome cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
			{relPath: "User Data/Default/Code Cache", kind: KindCache, risk: RiskSafe,
				desc: "Chrome code/JS cache (non-standard install path)",
				hint: "Delete Code Cache folder contents"},
			{relPath: "User Data/Default/Service Worker/CacheStorage", kind: KindCache, risk: RiskSafe,
				desc: "Chrome Service Worker cache (non-standard install path)",
				hint: "Delete CacheStorage folder contents"},
		},
	},
	{
		displayName:  "Microsoft Edge",
		nameTokens:   []string{"edge", "msedge", "microsoft edge"},
		markerExes:   []string{"msedge.exe", "edge.exe"},
		markerDirs:   []string{"user data"},
		minSizeBytes: 50 << 20,
		preyLocations: []preyLocation{
			{relPath: "User Data/Default/Cache", kind: KindCache, risk: RiskSafe,
				desc: "Edge cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
			{relPath: "User Data/Default/Code Cache", kind: KindCache, risk: RiskSafe,
				desc: "Edge code/JS cache (non-standard install path)",
				hint: "Delete Code Cache folder contents"},
		},
	},
	{
		displayName:  "Mozilla Firefox",
		nameTokens:   []string{"firefox", "火狐", "mozilla firefox"},
		markerExes:   []string{"firefox.exe"},
		markerDirs:   []string{"profiles.ini", "profiles"},
		minSizeBytes: 30 << 20,
		preyLocations: []preyLocation{
			// Firefox profiles are user-specific; we find the Profiles dir and
			// the matcher will look for */cache2 inside.
			// Here we flag the whole Profiles dir for awareness (RiskCaution).
			{relPath: "Profiles", kind: KindCache, risk: RiskCaution,
				desc: "Firefox profiles directory (non-standard install) — contains cache2 subdirs",
				hint: "Delete cache2 subdirs inside each profile, not the entire Profiles dir"},
		},
	},
	{
		displayName:  "Brave Browser",
		nameTokens:   []string{"brave", "brave browser", "brave-browser"},
		markerExes:   []string{"brave.exe", "brave browser.exe"},
		markerDirs:   []string{"user data"},
		minSizeBytes: 50 << 20,
		preyLocations: []preyLocation{
			{relPath: "User Data/Default/Cache", kind: KindCache, risk: RiskSafe,
				desc: "Brave cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
		},
	},
	{
		displayName:  "Discord",
		nameTokens:   []string{"discord"},
		markerExes:   []string{"discord.exe", "update.exe"},
		markerDirs:   []string{"cache", "code cache"},
		minSizeBytes: 10 << 20,
		preyLocations: []preyLocation{
			{relPath: "Cache", kind: KindCache, risk: RiskSafe,
				desc: "Discord cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
			{relPath: "Code Cache", kind: KindCache, risk: RiskSafe,
				desc: "Discord code cache (non-standard install path)",
				hint: "Delete Code Cache folder contents"},
		},
	},
	{
		displayName:  "Slack",
		nameTokens:   []string{"slack"},
		markerExes:   []string{"slack.exe"},
		markerDirs:   []string{"cache"},
		minSizeBytes: 10 << 20,
		preyLocations: []preyLocation{
			{relPath: "Cache", kind: KindCache, risk: RiskSafe,
				desc: "Slack cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
		},
	},
	{
		displayName:  "Microsoft Teams",
		nameTokens:   []string{"teams", "microsoft teams"},
		markerExes:   []string{"teams.exe", "ms-teams.exe"},
		markerDirs:   []string{"cache"},
		minSizeBytes: 10 << 20,
		preyLocations: []preyLocation{
			{relPath: "Cache", kind: KindCache, risk: RiskSafe,
				desc: "Teams cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
		},
	},
	{
		displayName:  "VS Code",
		nameTokens:   []string{"vscode", "vs code", "visual studio code", "code"},
		markerExes:   []string{"Code.exe", "code.exe"},
		markerDirs:   []string{"cache", "cacheddata", "cachedextensions"},
		minSizeBytes: 20 << 20,
		preyLocations: []preyLocation{
			{relPath: "Cache", kind: KindCache, risk: RiskSafe,
				desc: "VS Code cache (non-standard install path)",
				hint: "Delete Cache folder contents"},
			{relPath: "CachedData", kind: KindCache, risk: RiskSafe,
				desc: "VS Code cached extension data (non-standard install path)",
				hint: "Delete CachedData folder contents"},
		},
	},
	{
		displayName:  "WeChat",
		nameTokens:   []string{"wechat", "微信", "weixin"},
		markerExes:   []string{"WeChat.exe", "wechat.exe"},
		markerDirs:   []string{"wechat files"},
		minSizeBytes: 30 << 20,
		preyLocations: []preyLocation{
			// WeChat Files is a sibling, not child — we flag Cache inside it
			{relPath: "WeChat Files", kind: KindCache, risk: RiskCaution,
				desc: "WeChat Files directory (non-standard install) — contains Cache and media dirs",
				hint: "Clean Cache/Temp subdirs inside WeChat Files; do not delete FileStorage"},
		},
	},
	{
		displayName:  "Telegram",
		nameTokens:   []string{"telegram", "tg"},
		markerExes:   []string{"telegram.exe", "Telegram.exe"},
		markerDirs:   []string{"tdata"},
		minSizeBytes: 20 << 20,
		preyLocations: []preyLocation{
			{relPath: "tdata/user_data/cache", kind: KindCache, risk: RiskSafe,
				desc: "Telegram cache (non-standard install path)",
				hint: "Clear in Telegram settings > Data and Storage"},
		},
	},
	{
		displayName:  "Spotify",
		nameTokens:   []string{"spotify"},
		markerExes:   []string{"spotify.exe", "Spotify.exe"},
		markerDirs:   []string{"spotify_data", "spotifycrashservices"},
		minSizeBytes: 10 << 20,
		preyLocations: []preyLocation{
			{relPath: "Data", kind: KindCache, risk: RiskSafe,
				desc: "Spotify offline cache (non-standard install path)",
				hint: "Clear cache in Spotify settings"},
		},
	},
	{
		displayName:  "Zoom",
		nameTokens:   []string{"zoom"},
		markerExes:   []string{"zoom.exe", "Zoom.exe"},
		markerDirs:   []string{"logs", "zoomtemp"},
		minSizeBytes: 5 << 20,
		preyLocations: []preyLocation{
			{relPath: "logs", kind: KindLog, risk: RiskSafe,
				desc: "Zoom logs (non-standard install path)",
				hint: "Delete log files"},
		},
	},
	{
		displayName:  "OBS Studio",
		nameTokens:   []string{"obs", "obs studio", "obs-studio"},
		markerExes:   []string{"obs64.exe", "obs32.exe", "obs.exe"},
		markerDirs:   []string{"logs", "crashes"},
		minSizeBytes: 10 << 20,
		preyLocations: []preyLocation{
			{relPath: "logs", kind: KindLog, risk: RiskSafe,
				desc: "OBS Studio logs (non-standard install path)",
				hint: "Delete old log files"},
		},
	},
	{
		displayName:  "Steam",
		nameTokens:   []string{"steam"},
		markerExes:   []string{"steam.exe", "Steam.exe"},
		markerDirs:   []string{"steamapps"},
		minSizeBytes: 100 << 20,
		preyLocations: []preyLocation{
			{relPath: "steamapps/shadercache", kind: KindCache, risk: RiskSafe,
				desc: "Steam shader cache (non-standard install path)",
				hint: "Delete shader cache — Steam rebuilds automatically"},
			{relPath: "steamapps/downloading", kind: KindTemp, risk: RiskCaution,
				desc: "Steam incomplete downloads (non-standard install path)",
				hint: "Delete only if you no longer want these downloads"},
		},
	},
	{
		displayName:  "Adobe Creative Cloud",
		nameTokens:   []string{"adobe", "creative cloud", "adobecc"},
		markerExes:   []string{"AfterEffects.exe", "Premiere.exe", "Photoshop.exe", "Illustrator.exe"},
		markerDirs:   []string{"common", "media cache files", "media cache"},
		minSizeBytes: 100 << 20,
		preyLocations: []preyLocation{
			{relPath: "Common/Media Cache Files", kind: KindCache, risk: RiskSafe,
				desc: "Adobe Media Cache Files (non-standard install path)",
				hint: "Purge from Premiere Pro > Preferences > Media Cache"},
			{relPath: "Common/Media Cache", kind: KindCache, risk: RiskSafe,
				desc: "Adobe Media Cache (non-standard install path)",
				hint: "Purge from Premiere Pro > Preferences > Media Cache"},
		},
	},
}

// ─── Core discovery function ─────────────────────────────────────────────────

// AppDiscover scans directory entries for app installations in non-standard
// locations, returning synthesized Prey items using MSCM-inspired scoring.
//
// It is called from cmd/hunt.go after the initial scan, before rule matching.
func AppDiscover(dirs []string, minSize int64) []Prey {
	var result []Prey
	seen := make(map[string]bool)

	for _, dir := range dirs {
		if seen[dir] {
			continue
		}

		// Read immediate children once (needed for marker checks)
		children, err := readDirNames(dir)
		if err != nil {
			continue
		}

		for _, fp := range knownApps {
			signals := fp.computeSignals(dir, children, minSize)
			// Hard identity gate: require name_match OR marker_exe to fire.
			// Without at least one identity signal, structural matches (marker_dir
			// + size_tier + prey_exists) produce false positives on unrelated dirs
			// that happen to contain a subdirectory named "Cache" or "Data".
			hasIdentity := false
			for _, s := range signals {
				if s.layer == layerNameMatch || s.layer == layerMarkerExe {
					hasIdentity = true
					break
				}
			}
			if !hasIdentity {
				continue
			}
			score := mscmGate(signals)
			if score < 0.55 {
				continue // gate suppresses weak / single-layer matches
			}

			// Synthesize prey for each location that exists on disk
			for _, loc := range fp.preyLocations {
				preyPath := filepath.Join(dir, filepath.FromSlash(loc.relPath))
				if seen[preyPath] {
					continue
				}
				info, err := os.Stat(preyPath)
				if err != nil || !info.IsDir() {
					continue
				}

				// Measure size
				size := measureDirSize(preyPath)
				if size < minSize {
					continue
				}

				seen[preyPath] = true
				result = append(result, Prey{
					Path:        preyPath,
					SizeBytes:   size,
					Kind:        loc.kind,
					Risk:        loc.risk,
					Platform:    "all",
					Description: loc.desc,
					Action:      Action{Type: "manual", Hint: loc.hint},
				})
			}
		}
		seen[dir] = true
	}

	return result
}

// ─── Signal computation ───────────────────────────────────────────────────────

func (fp *appFingerprint) computeSignals(dir string, children []string, minSize int64) []appSignal {
	var signals []appSignal
	base := strings.ToLower(filepath.Base(dir))

	// Layer 1: name_match — fuzzy token overlap
	for _, tok := range fp.nameTokens {
		tok = strings.ToLower(tok)
		if base == tok || strings.Contains(base, tok) || strings.Contains(tok, base) {
			s := 1.0
			if base != tok {
				// partial match — score by overlap ratio
				s = float64(min(len(base), len(tok))) / float64(max(len(base), len(tok)))
				if s < 0.4 {
					s = 0.4 // floor: partial match still meaningful
				}
			}
			signals = append(signals, appSignal{layer: layerNameMatch, score: s})
			break
		}
	}

	// Layer 2: marker_exe — presence of a known executable
	for _, exe := range fp.markerExes {
		if hasChildCI(children, exe) {
			signals = append(signals, appSignal{layer: layerMarkerExe, score: 1.0})
			break
		}
	}

	// Layer 3: marker_dir — presence of a known subdirectory
	for _, mdir := range fp.markerDirs {
		if hasChildCI(children, mdir) {
			signals = append(signals, appSignal{layer: layerMarkerDir, score: 0.9})
			break
		}
	}

	// Layer 4: size_tier — directory size meets minimum expected
	if fp.minSizeBytes > 0 && minSize >= 0 {
		// We use minSize as a proxy: if the caller's configured minPreySize is
		// reasonable, large app dirs pass this. For a true size check we'd need
		// the dir size — but that's expensive here. Instead, check if at least
		// one prey subdir exists AND has children as a proxy for size.
		for _, loc := range fp.preyLocations {
			prey := filepath.Join(dir, filepath.FromSlash(loc.relPath))
			if st, err := os.Stat(prey); err == nil && st.IsDir() {
				// prey dir exists → directory is non-trivially sized
				signals = append(signals, appSignal{layer: layerSizeTier, score: 0.8})
				break
			}
		}
	}

	// Layer 5: prey_exists — at least one prey location is present on disk
	for _, loc := range fp.preyLocations {
		prey := filepath.Join(dir, filepath.FromSlash(loc.relPath))
		if st, err := os.Stat(prey); err == nil && st.IsDir() {
			signals = append(signals, appSignal{layer: layerPreyExists, score: 1.0})
			break
		}
	}

	return signals
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func readDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

// hasChildCI checks if name matches any entry case-insensitively.
func hasChildCI(children []string, name string) bool {
	lower := strings.ToLower(name)
	for _, c := range children {
		if strings.ToLower(c) == lower {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
