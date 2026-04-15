# Distrike CLI Output Design Rules

Based on *The Art of Unix Programming* (Eric S. Raymond) and classic Unix tool patterns.

## Core Principles

### 1. Each line = one unit of meaning

Traceroute prints one line per hop. `df` prints one line per filesystem. Distrike's `topo` prints one line per depth level in the critical path.

Never mix two semantic units on one line. If a user reads top-to-bottom, they should get a narrative.

### 2. Silence is golden

Only print what changes the user's decision. Skip healthy paths. Skip items below threshold. No "OK" lines in `topo`. No verbose status when nothing is wrong.

Applied: `topo` skips branches below 5% and doesn't print root node. `watch` only prints non-GREEN drives by default.

### 3. Summary header, then detail body

`top` gives 5 summary lines then the process table. Distrike's `topo` gives the verdict ("Tencent Files is eating 23%") BEFORE showing the proof.

The user should know the answer before reading the details. Details prove the answer, they don't deliver it.

### 4. Speak in the user's problem domain

Don't say "MFT entry 0x1A3F, cumSize 95328206848". Say "Documents — 94.4 GB". The user thinks in folders and applications, not MFT records.

Implementation details go to `--verbose` or `--debug`, never to default output.

### 5. Columns align, numbers right-justify

`ls -lh`, `df -h`, `lsblk` all right-align sizes so decimal points line up. Distrike's `status` table uses box-drawing with fixed column widths. Sizes right-aligned, paths left-aligned.

### 6. Indentation encodes hierarchy

`lsblk` uses tree-drawing characters to show disk > partition > filesystem. Distrike's `topo` uses indentation depth = directory depth. The user sees the funnel visually.

### 7. The punchline goes last on the line

`traceroute` puts latency at the end. `du` puts the path at the end. The eye scans left for context, lands right for the answer.

Distrike puts the percentage at the end of each line where the eye naturally stops.

### 8. Machine output is a separate mode

`--json` for machines. Pretty-print for humans. Never corrupt human output to make it parseable. Human mode tells the story; machine mode dumps the structure.

## Visual Design Rules

### Breathing room

Dense output is hostile. Add blank lines between logical sections (header / critical path / other branches). Use `│` connector lines between tree levels.

### Progressive disclosure

`status` = dashboard (1 second glance).
`topo` = diagnosis (10 second read).
`hunt` = prescription (action items).
`scan` = deep dive (full data).

Each command goes one level deeper. Users pick their depth.

### Color carries meaning, not decoration

| Color | Meaning | Used for |
|-------|---------|----------|
| Red #DA2626 | Danger | RED signal, kill-line breach |
| Amber rgb(255,193,7) | Warning | YELLOW signal, approaching |
| Green rgb(50,205,50) | Safe | GREEN signal |
| Purple rgb(147,51,234) | Critical | PURPLE signal, < 1 GB |

Colors match Windows Explorer (red) and Claude Code (amber, purple) for visual consistency across the user's environment.

### Box-drawing for dashboard, plain for flow

`status` uses `╭─╮│╰─╯` box-drawing because it's a dashboard — fixed layout, tabular data.

`topo` uses `└│━` minimal connectors because it's a flow — dynamic depth, narrative structure.

Don't mix the two styles.

## Anti-patterns

- **Data dump**: listing every directory is `du`, not topology analysis
- **Over-decoration**: emoji, ASCII art, or box-drawing where plain text suffices
- **Implementation leak**: showing MFT record counts or scan engine names in default output
- **Percentage-only**: "98% used" means nothing without knowing the total. Always show absolute sizes alongside percentages
- **Silent failure**: exit code 0 + no output when something went wrong. If the scan finds nothing, say so

## Reference Tools

| Tool | What it does right |
|------|-------------------|
| `traceroute` | One line per hop, tells a story of the journey |
| `df -h` | One line per filesystem, right-aligned sizes |
| `top` | Summary header + detail table, refreshing dashboard |
| `lsblk` | Tree-drawing for hierarchy, clean column alignment |
| `duf` | Box-drawing table, semantic grouping, color as signal |
| `dust` | Proportional bars next to filenames, horizontal stacked |
