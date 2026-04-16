# Distrike

**Your disk is full again. Distrike makes sure it's the last time.**

```
$ distrike status

C:\    [██████████████████████████████████████░░]  98.4%  7.4 GB free / 453 GB   DANGER
D:\    [██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  24.3%  3.4 TB free / 4.5 TB   OK
G:\    [████████████████████████████████████████]  99.5%  638 MB free / 115 GB   CRITICAL [USB]
```

```
$ distrike status   # on an HPC cluster (NCHC Taiwania-3 / TWCC)

/              [████████░░░░░░░░░░░░░░░░░░░]  28.9%   154.8 GB   217.7 GB   OK[xfs]
/boot          [██████░░░░░░░░░░░░░░░░░░░░░]  24.0%   770.2 MB   1014 MB    OK[xfs]
/gpfs-work     [██████████████████░░░░░░░░░]  66.9%   2.5 PB     7.5 PB     OK[gpfs]
/gpfs-home     [███████████████░░░░░░░░░░░░]  53.8%   820.2 TB   1.7 PB     OK[gpfs]
/home          [██░░░░░░░░░░░░░░░░░░░░░░░░░]   7.3%   12.4 PB    13.4 PB    OK[nfs]
/work          [███████████░░░░░░░░░░░░░░░░]  39.7%   8.1 PB     13.4 PB    OK[nfs]
```

One command. Every drive — from USB sticks to petabyte GPFS clusters. Four-color signal tells you exactly where you stand.

## Install

```bash
go install github.com/chen0430tw/distrike@latest
```

Or grab the binary from [Releases](https://github.com/chen0430tw/distrike/releases). Single static binary, no dependencies, no daemon required.

> **Windows SmartScreen?** Run `Unblock-File distrike.exe` in PowerShell, or right-click → Properties → Unblock.

## What it does

```bash
distrike status                      # see all drives at a glance
distrike topo C:                     # trace where space went
distrike hunt                        # find what can be cleaned
distrike clean --risk safe --yes     # clean it
distrike watch --install             # never get surprised again
```

**Topo traces the flow. Hunt finds the prey. Clean executes the strike. Watch prevents the rebound.**

## What it sees

190+ rules across every major cache, temp, and bloat source:

| | |
|---|---|
| **Caches** | pip, conda, npm, yarn, cargo, Go modules, Maven, Gradle, ccache |
| **AI / ML** | HuggingFace hub, PyTorch hub, TensorFlow, Singularity/Apptainer images |
| **Browsers** | Chrome, Edge, Firefox, Brave — cache only, never cookies or history |
| **IDEs** | VS Code, JetBrains, vim, emacs |
| **Apps** | Discord, Zoom, WeChat, QQ, OBS, Notepad++ |
| **Containers** | Docker, Podman, Singularity/Apptainer |
| **Virtual disks** | VHDX, VMDK, VDI — detect and compact |
| **System** | Windows Update, Temp, crash dumps, WER reports, Windows.old |
| **Gaming** | Steam shader cache, Epic Vault |
| **HPC** | CUDA kernel cache, NVIDIA shader cache, AMD shader cache |

Every item is risk-rated. SAFE cleans automatically. CAUTION asks first. DANGER is manual only.

Items marked `[cosmetic]` (thumbnail cache, font cache, etc.) are kept in the list for completeness but flagged — cleaning them has negligible real-world impact.

## HPC & Training Cluster Support

Distrike runs as a single static binary on any Linux node — no install, no root required.

```bash
# Upload once, run anywhere
scp distrike_linux user@cluster:/work/user/distrike

# Check all cluster filesystems at a glance
./distrike status

# Find what's silently eating your quota
./distrike hunt /home/user
./distrike hunt /work/user
```

**First run on NCHC Taiwania-3** found 31.1 GB recoverable immediately:

```
[SAFE]  26.2 GB  /home/user/.singularity/cache
  Kind: cache  Description: Singularity image layer cache
  Cleanup: singularity cache clean --force

[SAFE]   4.9 GB  /home/user/.cache/pip
  Kind: cache  Description: pip wheel/package download cache
  Cleanup: pip cache purge

Total: 2 prey, 31.1 GB reclaimable
```

### Model weight inventory

Training runs accumulate checkpoints. Enable model weight scanning to audit them:

```bash
distrike config set hunt.scan_model_weights true
distrike hunt /work/user
```

```
[CAUTION]  708 MB  /work/user/qc20k_vb_full/checkpoint_step_20000.pt
[CAUTION]  708 MB  /work/user/qc20k_plain_full/checkpoint_step_20000.pt
[CAUTION]  516 MB  /work/user/qc20k_transformer_vb/checkpoint_step_20000.pt
...
Total: 16 prey, 6.2 GB  — training checkpoints across experiment directories
```

Detects: `.safetensors` `.gguf` `.ggml` `.pt` `.pth` `.ckpt` `.h5` `.hdf5` `.onnx` `.pb`

CAUTION-rated — Distrike reports them, never auto-deletes.

### Filesystem awareness

Distrike identifies filesystem type in the signal column and adapts signal thresholds:

| Filesystem | Seen on | Notes |
|---|---|---|
| `gpfs` | IBM Spectrum Scale clusters | PB-scale shared storage |
| `wekafs` | Weka HPC clusters | High-perf NVMe-over-fabric |
| `nfs` | Most clusters | Quota management critical |
| `xfs` | Linux compute nodes | Default HPC OS filesystem |
| `vfat` | /boot/efi | Small system partition — no false CRITICAL |
| `tmpfs` | /dev/shm, fake mounts | Visible when user-created |
| `ReFS` | Windows Server | fastwalk engine, no MFT |

Small system partitions (`/boot`, `/boot/efi`) never trigger false CRITICAL signals — thresholds scale with partition size.

### What HPC users typically recover

| Source | Typical size | Notes |
|---|---|---|
| Singularity/Apptainer cache | 5–50 GB | Container image layers, re-downloadable |
| HuggingFace hub cache | 10–200 GB | Model weights, re-downloadable |
| PyTorch hub cache | 1–50 GB | Pre-trained models |
| pip cache | 500 MB–5 GB | Wheel files, always regenerable |
| conda pkgs | 2–10 GB | Package tarballs after env creation |
| Old training checkpoints | 500 MB–50 GB | `.pt`/`.ckpt` from abandoned runs |

## What it never touches

- Cookies, browsing history, saved passwords, bookmarks
- Windows Run history, Recent files, jump lists
- Your documents, projects, source code, or model weights (unless you explicitly enable `scan_model_weights`)

## Why the signal isn't based on percentage

A 1 TB drive at 97% still has 30 GB free. A 120 GB drive at 99% has 600 MB. Same progress bar. Completely different danger.

Distrike uses **absolute free space** against a kill-line threshold:

| Signal | Condition | |
|--------|-----------|---|
| **PURPLE** | < 1 GB | Imminent failure |
| **RED** | < kill-line (default 20 GB) | Cleanup now |
| **YELLOW** | < kill-line × 1.5 | Attention |
| **GREEN** | Above threshold | Safe |

Small partitions (total < kill-line) use proportional thresholds instead, so `/boot/efi` with 194 MB free out of 200 MB shows **OK**, not CRITICAL.

### Why 20 GB is the default kill-line

Below 20 GB, Windows enters a **death spiral** — the system starts consuming space faster than you can free it:

| What happens | Space needed | Effect when starved |
|---|---|---|
| **pagefile.sys expansion** | 3–5 GB | Low memory → Windows grows virtual memory → eats more space |
| **Windows Update** | ~8 GB | Patches need temp space to unpack → fail and rollback (uses more space) |
| **VHDX bloat** | 2–3 GB | WSL/Docker VHDX can't compact without temp space → only grows |
| **NTFS fragmentation** | — | No contiguous free blocks → MFT fragments → performance collapses |
| **App temp files** | 2–3 GB | Chrome, VS Code, games write temp files → write fails → crash |

Total: **~18–20 GB minimum buffer** for normal system operations.

The math: when free space `F` drops below kill-line `K`, a positive feedback term `S(F)` activates:

```
Normal:     dF/dt = -C(t)                    (linear cache growth)
Below K:    dF/dt = -C(t) - α(K - F)²/K      (system self-consumption)
```

The less space you have, the more space the system consumes. Survival requires cleanup rate `R > C(t) + S(F)`, which becomes impossible as `F → 0`.

`K = B_page + B_update + B_vhdx + B_app = 5 + 8 + 3 + 3 ≈ 20 GB`

This is why it's called a **kill-line**, not a warning line. Cross it, and you can't recover without manual intervention. Full derivation in [DESIGN.md](docs/DESIGN.md).

### The rebound problem

Cleaning disk space is temporary. Caches rebuild silently:

| Source | Behavior | Rebound |
|---|---|---|
| QQ/WeChat media cache | Every image you view is saved locally | Continuous growth |
| Chat databases (nt_db) | Append-only, never auto-purged | Only grows |
| WSL/Docker VHDX | Expands on use, never auto-shrinks | Only grows |
| pagefile.sys | Grows when RAM is pressured | Dynamic |
| Windows Update | Monthly patches + old version backups | ~1–2 GB/month |
| Dev caches (npm, pip, cargo) | Downloaded on every `install` | Rebuilds after clean |

You clean 5 GB today. Tomorrow it's back. That's why `distrike watch` exists — it monitors the rebound and alerts before you cross the kill-line again.

## How it scans

Three engines. Automatic selection.

| Engine | Speed | Hidden files | Requires |
|--------|-------|:---:|----------|
| **MFT** | 18s / 454 GB | Yes | Windows Admin + NTFS |
| **fastwalk** | 15s / 454 GB | — | Any platform |
| **Cache** | Instant | — | Previous scan |

The MFT engine reads the NTFS Master File Table directly — same technique antivirus and forensic tools use. Custom binary parser, 1 MB batch I/O, parallel pipeline. It sees everything including `hiberfil.sys` and system-hidden files.

**ReFS volumes** are automatically detected and always use fastwalk — ReFS has no MFT or USN Journal. Distrike prints a note when this happens.

## Topology analysis (`topo`)

Not a tree listing. A critical path trace — follows the largest directory at each level straight to the deepest space sink.

```
$ distrike topo C:

  C:\  448 GB used, 5.5 GB free  DANGER
  Tencent Files is eating 23% (88.8 GB)

    ━━━━━━━━━━━━━━━━━━━━━━━ Users                204.6 GB    53%
    │
    └ ━━━━━━━━━━━━━━━━━━━━━━━ asus                 201.8 GB    52%
      │
      └ ━━━━━━━━━━ Documents             94.4 GB    24%
        │
        └ ━━━━━━━━━━ Tencent Files         88.8 GB    23% ◀

  Program Files           68.9 GB  ━━━━━━━━   18%
  Windows                 39.5 GB  ━━━━   10%
```

The verdict comes first. The critical path proves it. Other branches are listed below for context.

| Mode | What you get |
|------|---|
| **As Admin** | Full critical path trace with cumulative sizes from MFT engine |
| **Without Admin** | Top-level directory breakdown (no drill-down) |

Run as Administrator for the complete topology.

Built on [Tensorearch](https://github.com/chen0430tw/Tensorearch) topology graph architecture — directories as nodes, parent-child as edges, cumulative size as weight propagation.

## How watch works

Caches rebuild silently. Distrike watches for it.

| Signal | Poll interval |
|--------|:---:|
| PURPLE | 10 seconds |
| RED | 30 seconds |
| YELLOW | 5 minutes |
| GREEN | 15 minutes |

The worse it gets, the faster it checks. `--auto-clean` triggers cleanup automatically.

Desktop notifications fire when:
- A drive's signal **worsens** (e.g. YELLOW → RED)
- Free space **drops >50%** within the same signal level (e.g. RED 10 GB → RED 1.3 GB)

Click the notification to open the affected drive in Explorer. USB drives don't steal focus from system drives.

```bash
distrike watch                # foreground
distrike watch --auto-clean   # auto-cleanup on RED/PURPLE
distrike watch --install      # background service (Windows/macOS/Linux)
```

## Time filters

```bash
distrike scan C: --after 3d          # what grew in last 3 days
distrike hunt --after yd             # prey since yesterday
distrike scan D: --after tw          # this week's growth
```

fd-style shortcuts: `td` `yd` `3d` `7d` `tw` `lw` `tm` `lm` `ty` `ly` `@timestamp` `YYYY-MM-DD`

## Agent-friendly

Every command supports `--json`. Built for AI agent workflows:

```bash
distrike status --json
distrike hunt --json
distrike clean --risk safe --yes --json
```

## Configuration

```bash
distrike config set kill_line 30GB
distrike config set hunt.scan_model_weights true   # enable model weight inventory
distrike config whitelist add "D:\MyProject"
```

Don't want cargo cache cleaned? One command:

```bash
distrike config whitelist add ~/.cargo/registry
```

Config: `%APPDATA%\distrike\config.yaml` (Windows) / `~/.config/distrike/config.yaml` (Linux/macOS)

## All commands

| Command | What it does |
|---------|---|
| `status` | Four-color signal for every drive |
| `topo` | Critical path trace — where space flows and sinks |
| `scan` | Top space consumers with time filters |
| `hunt` | Find cleanable prey with risk assessment |
| `clean` | Execute the strike |
| `watch` | Capacity rebound monitor with notifications |
| `config` | Kill-line, whitelist, custom rules |
| `wsl` | WSL distribution space management |
| `version` | Print version (`-v` / `--version`) |

## Platforms

| | MFT engine | Watch service | Notes |
|---|:---:|---|---|
| **Windows 10/11** | Yes | schtasks | Full feature set |
| **Linux / WSL2** | — | systemd | HPC clusters, servers |
| **macOS** | — | launchd | |

Tested on:
- NCHC Taiwania-3 (wekafs, H100/H200, Slurm)
- TWCC Taiwania-2 (gpfs/nfs, V100, Slurm)
- Standard Ubuntu/Debian servers
- WSL2 (ext4 inside VHDX)

## Under the hood

Built on [Tensorearch](https://github.com/chen0430tw/Tensorearch) topology graph architecture — directory trees as node-edge-weight propagation networks.

- **Signal**: CFPAI four-light risk classification with small-partition correction
- **MFT engine**: Möbius ring + OPU batch I/O + Cardinal Bitset index ([paper](docs/cardinal_bitset.pdf))
- **Language**: Go (selected via Tree Diagram analysis, score 0.917)
- **Cache**: SQLite, pure Go, no CGO
- **Quality**: Tensorearch 20-language diagnose, 32/32 PASS

## Origin

Cleaned 33.7 GB manually. Three days later, C: was full again — QQ wrote 15.6 GB, Claude VM grew 9.3 GB, caches rebuilt silently.

Built Distrike so it never happens again. Then took it to a training cluster and found 31 GB of Singularity cache on the first scan.

## License

MIT
