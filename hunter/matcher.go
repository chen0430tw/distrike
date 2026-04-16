package hunter

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"distrike/scanner"
)

// Matcher evaluates directory entries against rules to identify prey.
type Matcher struct {
	rules     []Rule
	whitelist []string
	minSize   int64
}

// NewMatcher creates a matcher with the given rules and whitelist.
func NewMatcher(rules []Rule, whitelist []string, minSize int64) *Matcher {
	return &Matcher{rules: rules, whitelist: whitelist, minSize: minSize}
}

// Match checks all entries against rules and returns identified prey.
func (m *Matcher) Match(entries []scanner.DirEntry) []Prey {
	var result []Prey
	seen := make(map[string]bool) // deduplicate paths

	for _, entry := range entries {
		if seen[entry.Path] {
			continue
		}
		if m.isWhitelisted(entry.Path) {
			continue
		}
		if rule, ok := m.matchRule(entry.Path); ok {
			seen[entry.Path] = true
			size := entry.SizeBytes
			// If size is 0 (CollectAll directory), measure it
			if size == 0 && entry.IsDir {
				size = measureDirSize(entry.Path)
			}
			// Skip tiny matches
			if size < m.minSize {
				continue
			}
			prey := Prey{
				Path:        entry.Path,
				SizeBytes:   size,
				Kind:        rule.Kind,
				Risk:        rule.Risk,
				Platform:    rule.Platform,
				Description: rule.Description,
				Action:      rule.Action,
				LastAccess:  entry.LastModified,
				Cosmetic:    rule.Cosmetic,
			}
			result = append(result, prey)
		}
	}

	// Deduplicate: if a parent and child both match, keep only the parent
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Path) < len(result[j].Path) // shorter paths first
	})
	var deduped []Prey
	for _, p := range result {
		isChild := false
		for _, kept := range deduped {
			parentPath := filepath.ToSlash(kept.Path)
			childPath := filepath.ToSlash(p.Path)
			if strings.HasPrefix(childPath, parentPath+"/") {
				isChild = true
				break
			}
		}
		if !isChild {
			deduped = append(deduped, p)
		}
	}

	// Sort by size descending
	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].SizeBytes > deduped[j].SizeBytes
	})

	return deduped
}

// matchRule finds the first rule that matches the given path.
func (m *Matcher) matchRule(path string) (Rule, bool) {
	// Normalize path separators to forward slashes for consistent matching.
	normalized := filepath.ToSlash(path)

	for _, rule := range m.rules {
		if matchPattern(normalized, rule.Pattern) {
			return rule, true
		}
	}
	return Rule{}, false
}

// matchPattern checks if a path matches a glob-style pattern.
// Supports:
//   - "*" prefix patterns like "*/pip/cache" — matches as a suffix anywhere in the path
//   - Extension patterns like "*.vhdx" — matches file extension
//   - Exact filepath.Match patterns
func matchPattern(path, pattern string) bool {
	pattern = filepath.ToSlash(pattern)

	// Skip runtime-detect patterns (handled separately).
	if strings.HasPrefix(pattern, "__runtime_detect__") {
		return false
	}

	// Extension match: "*.ext"
	if strings.HasPrefix(pattern, "*.") && !strings.Contains(pattern[2:], "/") {
		ext := pattern[1:] // e.g., ".vhdx"
		return strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext))
	}

	// Suffix match: "*/some/path" — check if path ends with the suffix after "*/"
	if strings.HasPrefix(pattern, "*/") {
		suffix := pattern[1:] // e.g., "/pip/cache" or "/Tencent Files/*/Cache"
		// Fast path: no wildcards in suffix — plain string check.
		if !strings.ContainsAny(suffix, "*?[") {
			return strings.HasSuffix(path, suffix) || strings.Contains(path, suffix+"/")
		}
		// Suffix contains wildcards (e.g. "*/Tencent Files/*/Cache").
		// Try filepath.Match against every possible tail of the path so that
		// a pattern like "/Tencent Files/*/Cache" matches
		// "C:/Users/x/Documents/Tencent Files/2304790021/Cache".
		tail := path
		for {
			idx := strings.Index(tail, "/")
			if idx < 0 {
				break
			}
			candidate := tail[idx:] // starts with "/"
			if matched, _ := filepath.Match(suffix, candidate); matched {
				return true
			}
			// Also check parent-of-path (suffix+"/...") for contains-style matching.
			if matched, _ := filepath.Match(suffix, strings.TrimRight(candidate, "/")); matched {
				return true
			}
			tail = tail[idx+1:]
		}
		return false
	}

	// Absolute pattern or exact match: try filepath.Match on the last components.
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}

	// Also try matching just the base name for simple patterns.
	base := filepath.Base(path)
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	// Contains match as fallback for absolute patterns like "/var/cache/apt".
	if !strings.Contains(pattern, "*") {
		return strings.HasSuffix(path, pattern) || path == pattern
	}

	return false
}

// measureDirSize walks a directory to measure its total size.
// Used when CollectAll mode returns directories with size=0.
func measureDirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// isWhitelisted checks if a path matches any whitelist pattern.
func (m *Matcher) isWhitelisted(path string) bool {
	normalized := filepath.ToSlash(path)
	for _, wl := range m.whitelist {
		wl = filepath.ToSlash(wl)
		// Handle "*/suffix" patterns consistently with matchPattern:
		// "*/WeChat Files" whitelists any path that ends with or contains "/WeChat Files".
		if strings.HasPrefix(wl, "*/") {
			suffix := wl[1:] // e.g., "/WeChat Files" or "/QQNT/*/nt_db"
			if !strings.ContainsAny(suffix, "*?[") {
				if strings.HasSuffix(normalized, suffix) || strings.Contains(normalized, suffix+"/") {
					return true
				}
			} else {
				// Wildcard suffix — try against every tail (same logic as matchPattern).
				tail := normalized
				for {
					idx := strings.Index(tail, "/")
					if idx < 0 {
						break
					}
					candidate := tail[idx:]
					if matched, _ := filepath.Match(suffix, candidate); matched {
						return true
					}
					tail = tail[idx+1:]
				}
			}
			continue
		}
		// Exact match.
		if normalized == wl {
			return true
		}
		// Suffix/contains match.
		if strings.HasSuffix(normalized, wl) {
			return true
		}
		// Glob match.
		if matched, _ := filepath.Match(wl, normalized); matched {
			return true
		}
		// Check if path is under a whitelisted directory.
		if strings.HasPrefix(normalized, wl+"/") {
			return true
		}
	}
	return false
}
