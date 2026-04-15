# Distrike

**Disk + Strike** — Cross-platform disk space kill-line detector with capacity rebound monitoring.

Distrike answers: **"What should be cleaned? How long until danger? Is it critical?"**

## Quick Start

```bash
# Check all drives
distrike status

# Find cleanable items
distrike hunt C:

# Auto-clean safe items
distrike clean --risk safe --yes

# What grew in last 3 days?
distrike scan C: --after 3d

# Enable real-time monitoring
distrike watch --install
```

## Install

```bash
# From source
go install github.com/chen0430tw/distrike@latest

# Or download binary from GitHub Releases
# Check version
distrike -v
```

### Windows SmartScreen

Downloaded exe files may trigger SmartScreen ("Windows protected your PC"). Fix:

```powershell
# Remove the internet download mark
Unblock-File distrike.exe
```

Or: right-click `distrike.exe` → Properties → check "Unblock" → OK.

Building from source (`go install`) never triggers SmartScreen.

### What it does NOT touch

Distrike only cleans filesystem caches and temp files. It will **never** delete:
- Browser cookies, history, passwords, or bookmarks
- Windows Run history or Recent files
- Any user documents or project files

## How It Works

Distrike **auto-detects all mounted drives** — 1 drive or 10 drives, internal SSD or USB stick. No configuration needed. Removable drives are tagged `[USB]`.

Signal is based on **free space in bytes**, not percentage — a 1 TB drive at 97% (30 GB free) is safer than a 120 GB drive at 99% (600 MB free), even though both progress bars look similar.

## Features

### Four-Color Capacity Signal (CFPAI-derived)

```
C:\    [███████████████████████████████████████░░]  98.4%  7.4 GB free / 453 GB  DANGER
D:\    [███████████████████████████████████████░░]  97.0%  28.9 GB free / 953 GB  WARNING
E:\    [██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  24.3%  3.4 TB free / 4.5 TB  OK
G:\    [████████████████████████████████████████]  99.5%  638 MB free / 115 GB   CRITICAL [USB]
```

| Signal | Condition | Meaning |
|--------|-----------|---------|
| GREEN | Free > kill-line × 1.5 | Safe |
| YELLOW | Approaching kill-line | Attention |
| RED | Below kill-line (default 20 GB) | Danger, cleanup recommended |
| PURPLE | < 1 GB free | Critical, near exhaustion |

### 80+ Prey Identification Rules

Automatically detects cleanable items across platforms:

| Category | Examples |
|----------|---------|
| Cache | pip, npm, cargo, gradle, conda, huggingface, homebrew |
| Browser | Chrome, Edge, Firefox (cache, code cache, service worker) |
| IDE | VS Code, JetBrains (caches, index, logs) |
| Electron | Discord, Slack, Teams (cache, GPU cache) |
| Virtual Disk | VHDX, VMDK, VDI (detect + compact) |
| Temp | Windows Temp, crash dumps, recycle bin |
| Backup | iPhone/iPad, Windows Image |
| System | Windows Update cache, prefetch |
| Creative | Adobe Media Cache |
| Gaming | Steam shader cache, Epic Vault |

Each prey includes risk level (SAFE/CAUTION/DANGER) and actionable cleanup command.

### Three Scan Engines

| Engine | Speed | Sees Hidden Files | Requires |
|--------|-------|:-----------------:|----------|
| **MFT** | 18s / 454GB | Yes (hiberfil.sys) | Windows Admin + NTFS |
| **fastwalk** | 15s / 454GB | No | Any platform |
| **SQLite cache** | Instant | N/A | Previous scan |

MFT engine uses custom binary parser with Möbius ring architecture:
- OPU-style 1MB batch I/O (1000× fewer syscalls)
- NTFS fixup + $ATTRIBUTE_LIST resolution
- Parallel N-worker parsing pipeline

### Capacity Rebound Monitor (`watch`)

AV-inspired real-time monitoring — adaptive polling based on danger level:

| Signal | Poll Interval | Reason |
|--------|:------------:|--------|
| PURPLE | 10s | Imminent danger |
| RED | 30s | Below kill-line |
| YELLOW | 5 min | Trend observation |
| GREEN | 15 min | Heartbeat |

```bash
distrike watch                # foreground monitoring
distrike watch --auto-clean   # auto-run 'clean --risk safe' on RED/PURPLE
distrike watch --no-notify    # disable desktop notifications
distrike watch --install      # background service (schtasks/launchd/systemd)
distrike watch --status       # check if running
distrike watch --uninstall    # remove service
```

Desktop notifications (Windows balloon tip / macOS / Linux notify-send) fire automatically when signals worsen to RED or PURPLE.

### Agent-Friendly

Every command supports `--json` for structured output:

```bash
# AI Agent workflow
distrike status --json        # check signals
distrike hunt --all --json    # find prey with cleanup commands
distrike clean --risk safe --yes --json   # auto-clean
```

### Time Filter (fd-style)

```bash
distrike scan C: --after 3d          # what grew in last 3 days
distrike hunt C: --after yd          # prey modified since yesterday
distrike scan D: --after tw          # this week's growth
distrike scan C: --after 2026-04-01  # since specific date
```

Shortcuts: `td` (today), `yd` (yesterday), `3d/7d/30d` (days ago), `tw/lw` (this/last week), `tm/lm` (this/last month), `ty/ly` (this/last year), `@timestamp` (unix)

## Commands

| Command | Description |
|---------|-------------|
| `status` | Kill-line status with four-color signals |
| `scan` | Scan directories, show top space consumers |
| `hunt` | Identify cleanable prey with risk assessment |
| `clean` | Execute cleanup (with dry-run and confirmation) |
| `watch` | Real-time capacity rebound monitoring |
| `config` | View/modify configuration (set, whitelist, rules) |
| `wsl` | WSL distribution management (list, compact, hunt) |

## Configuration

```bash
distrike config set kill_line 20GB
distrike config set signal.thresholds.yellow.used_ratio 0.75
distrike config whitelist add "D:\MyImportantProject"
distrike config rule add --pattern "*/MyApp/cache" --kind cache --risk safe
```

Config file: `%APPDATA%\distrike\config.yaml` (Windows) / `~/.config/distrike/config.yaml` (Linux/macOS)

## Platforms

| Platform | Status | MFT Engine | Watch Service |
|----------|:------:|:----------:|---------------|
| Windows 10/11 | Tested | Available | schtasks |
| Linux / WSL2 | Tested | N/A | systemd user |
| macOS | Compiles | N/A | launchd |

## Architecture

- **Language**: Go (selected via Tree Diagram analysis, score 0.917)
- **License**: MIT (selected via Tree Diagram + HCE analysis, score 0.81)
- **Signal System**: Ported from treesea/CFPAI four-light risk signal
- **MFT Engine**: Möbius ring + OPU batch I/O + Cardinal Bitset index ([paper PDF](docs/cardinal_bitset.pdf) | [LaTeX source](docs/cardinal_bitset.tex))
- **Scan Cache**: SQLite (modernc.org/sqlite, pure Go, no CGO)
- **Code Quality**: Verified by Tensorearch 20-language diagnose (32/32 PASS)

## Origin Story

Developer cleaned 33.7 GB of disk space manually. Three days later, C: drive was nearly full again — QQ wrote 15.6 GB, Claude VM grew 9.3 GB, caches rebuilt silently. Distrike was built so that never happens again.

## License

MIT
