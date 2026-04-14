# Distrike - Development Standards

## Project Overview

Distrike (Disk + Strike) is a cross-platform, Agent-friendly disk space analyzer with kill-line alerts, four-color capacity signals (CFPAI-derived), and automated prey identification.

**Language:** Go 1.22+
**CLI Framework:** github.com/spf13/cobra
**Config:** gopkg.in/yaml.v3
**No CGO:** All dependencies must be pure Go

## Architecture

```
main.go          → cmd/       → killline/  (drive enumeration)
                               → scanner/   (fastwalk/MFT scan engines)
                               → signal/    (four-color capacity signal)
                               → hunter/    (prey identification rules)
                               → health/    (SMART/capacity anomaly)
                               → security/  (encryption/permissions)
                               → config/    (YAML config management)
                               → output/    (JSON/text rendering)
                               → vdisk/     (virtual disk detection)
                               → wsl/       (WSL management, Windows only)
                               → cleaner/   (cleanup execution)
```

## Coding Standards

### 1. Package Design
- Each package has ONE responsibility
- Package-level types are exported; implementation helpers are unexported
- No circular imports — dependency flows: cmd → {scanner, hunter, signal, ...} → config
- Platform-specific code uses build tags: `//go:build windows`, `//go:build linux || darwin`

### 2. Error Handling
- Return `error`, never panic
- Wrap errors with context: `fmt.Errorf("scanning %s: %w", path, err)`
- Access denied errors → record in AccessReport, don't fail the scan
- Missing optional tools (Docker, smartctl) → skip gracefully, note in output

### 3. Output Convention
- ALL commands support `--json` flag
- Human-readable output → stdout
- Progress/status → stderr (don't pollute JSON stdout)
- JSON schema includes `schema_version`, `tool`, `tool_version`, `timestamp`, `platform`
- Exit codes: 0=OK, 1=WARNING/CRITICAL found, 2=execution error

### 4. Configuration
- Config struct lives in `config/config.go`
- Default values defined in `DefaultConfig()`
- All config fields have YAML tags
- Config path: Windows=%APPDATA%\distrike, macOS=~/Library/Application Support/distrike, Linux=~/.config/distrike

### 5. Naming
- Types: PascalCase (`DirEntry`, `ScanResult`)
- Functions: PascalCase for exported, camelCase for internal
- Constants: PascalCase (`KindCache`, `RiskSafe`)
- Files: snake_case (`drive_windows.go`, `rules_darwin.go`)
- Build tag files: `<base>_<platform>.go`

### 6. Testing
- Test files: `*_test.go` in same package
- Table-driven tests preferred
- Test helpers unexported, prefixed with `test` or in `testdata/`

### 7. JSON Output Schema

Every command's JSON output wraps in:
```json
{
  "schema_version": "1.0",
  "tool": "distrike",
  "tool_version": "0.1.0",
  "timestamp": "2006-01-02T15:04:05Z07:00",
  "platform": "windows",
  "data": { ... }
}
```

### 8. Size Handling
- Internal: always int64 bytes
- User-facing: parse/format human sizes ("20GB", "100MB")
- Use shared `parseSize()` / `formatSize()` in a `internal/units` package

### 9. Dependencies (go.mod)

Required:
- `github.com/spf13/cobra` — CLI framework
- `gopkg.in/yaml.v3` — config parsing
- `github.com/charlievieth/fastwalk` — concurrent directory traversal
- `github.com/shirou/gopsutil/v3` — cross-platform disk info
- `golang.org/x/sys` — Windows/Unix system calls

Phase 3+:
- `modernc.org/sqlite` — scan cache (pure Go SQLite)

Phase 4+:
- `github.com/Velocidex/go-ntfs` — MFT direct read

### 10. File Ownership Map (for parallel development)

| Module | Files | Owner |
|--------|-------|-------|
| foundation | main.go, go.mod, internal/units/ | Agent-Foundation |
| cmd | cmd/*.go | Agent-CLI |
| config | config/config.go | Agent-Foundation |
| killline | killline/*.go | Agent-Foundation |
| scanner | scanner/*.go | Agent-Scanner |
| signal | signal/*.go | Agent-Scanner |
| hunter | hunter/*.go | Agent-Hunter |
| health | health/*.go | Agent-Hunter |
| security | security/*.go | Agent-Hunter |
| output | output/*.go | Agent-CLI |
| vdisk | vdisk/*.go | Agent-Hunter |
| wsl | wsl/*.go | Agent-CLI |
| cleaner | cleaner/*.go | Agent-CLI |
