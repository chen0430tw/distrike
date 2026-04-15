# Distrike - 跨平台磁盘空间斩杀线检测器

## 设计文档 v0.4

---

## 1. 项目定位

Distrike 是一个跨平台、Agent 友好的磁盘空间分析与斩杀线预警工具。

名字来源：**Disk + Strike**（磁盘斩杀）

### 与现有工具的关系

| 工具 | 定位 | 局限 |
|------|------|------|
| WizTree | GUI 磁盘分析，MFT 直读，3秒/TB | 闭源，无 CLI，Windows only |
| Everything | 文件搜索引擎，MFT + USN | 不分析空间，需后台常驻，Windows only |
| WinDirStat | GUI treemap 可视化 | 慢（单线程），无 CLI，Windows only |
| gdu | Go TUI 磁盘分析，goroutine 并发 | 无斩杀线，无清理建议，无猎物识别 |
| dust | Rust 终端 bar chart，Rayon 并发 | 无斩杀线，无清理建议 |
| dua-cli | Rust TUI + 交互删除 | 无智能识别，无 Agent 输出 |
| ncdu | C/Zig 终端 TUI | POSIX only，无 Windows |
| Distrike | **跨平台 CLI 磁盘斩杀线检测** | 不做 GUI，不做文件搜索 |

### 核心差异

现有工具回答：**"什么东西占了多少空间？"**

Distrike 回答：**"哪些东西应该被清理？还能撑多久？危险吗？"**

### 独特功能组合（现有工具均未同时具备）

1. **斩杀线预警系统** — 不只是显示大小，而是判断"危不危险"
2. **猎物自动识别** — 30+ 内建规则，自动分类 + 给出清理命令
3. **Agent 友好 JSON** — 机器可直接解析和执行
4. **跨平台统一体验** — Windows / macOS / Linux / WSL
5. **扫描缓存** — 借鉴 gdu，SQLite 缓存扫描结果，重复查看秒开
6. **虚拟磁盘感知** — VHDX/VMDK/VDI/qcow2 检测 + 压缩建议

---

## 2. 核心概念

### 2.1 斩杀线 (Kill Line)

用户自定义的剩余空间警戒线（默认 20 GB）。

#### 20 GB 默认值的数学依据

低于 20 GB 时，Windows 进入**死亡螺旋**——系统消耗空间的速度超过用户释放空间的速度：

| 系统行为 | 所需缓冲 | 空间不足时的后果 |
|---------|---------|----------------|
| pagefile.sys 动态扩容 | 3–5 GB | 内存压力 → 虚拟内存膨胀 → 吃掉更多空间 |
| Windows Update 解包 | ~8 GB | 补丁需要临时空间 → 失败回滚（占用更多空间） |
| VHDX 压缩操作 | 2–3 GB | WSL/Docker VHDX 无临时空间无法 compact → 只增不减 |
| NTFS 碎片化 | — | 无连续空闲块 → MFT 频繁碎片分配 → 性能崩溃 |
| 应用临时文件 | 2–3 GB | Chrome/VS Code/游戏写临时文件 → 写入失败 → 崩溃 |

**合计：~18–20 GB 最低系统操作缓冲区。**

低于此线，系统自我吞噬：空间越少 → 需要越多空间 → 空间越来越少。这就是为什么叫"斩杀线"而不是"警告线"——越过后无法自动恢复，必须人工干预。

#### 容量反弹问题

清理磁盘空间是临时的。缓存会静默重建：

| 来源 | 行为模式 | 反弹特征 |
|------|---------|---------|
| QQ/微信媒体缓存 | 每张浏览的图片本地保存 | 持续增长 |
| 聊天数据库 (nt_db) | 只追加不清理 | 只增不减 |
| WSL/Docker VHDX | 使用时膨胀，不自动收缩 | 只增不减 |
| pagefile.sys | 内存压力时动态增长 | 动态波动 |
| Windows Update | 每月补丁 + 旧版本备份 | ~1–2 GB/月 |
| 开发缓存 (npm/pip/cargo) | 每次 install 重新下载 | 清完即重建 |

这就是 `distrike watch` 存在的意义——监控反弹，在重新越线之前告警。

### 2.2 容量灯号系统 (Capacity Signal)

借鉴 treesea/CFPAI 的四灯风险信号体系，将磁盘空间映射为四色灯号。

CFPAI 原版使用 `total_exposure`（仓位比例）+ `HHI`（集中度）+ `risk_budget`（风险预算）三维判定。
Distrike 映射为 `used_ratio`（已用空间比例）+ `concentration`（单一大户集中度）+ `free_budget`（剩余空间预算）。

**四色灯号：**

| 灯号 | 颜色 | 触发条件 | 含义 |
|------|------|----------|------|
| GREEN | 绿 | 默认（其余均不满足） | 空间充裕，无需操作 |
| YELLOW | 黄 | `used_ratio > 0.70` 或 `concentration > 0.35` | 空间趋紧或单一大户过度集中 |
| RED | 红 | `used_ratio > 0.85` 且 `concentration > 0.5` | 空间危险，建议立即清理 |
| PURPLE | 紫 | `used_ratio > 0.90` 且 `concentration > 0.6` 且 `free < kill_line` | 极度危险/黑天鹅级（即将耗尽） |

**判定逻辑（优先级由高到低）：**

```go
func classifyDrive(usedRatio, concentration float64, freeBytes, killLine int64) Signal {
    freeBudget := float64(freeBytes) / float64(killLine)
    if usedRatio > 0.90 && concentration > 0.6 && freeBudget < 1.0 {
        return PURPLE  // 极度危险
    }
    if usedRatio > 0.85 && concentration > 0.5 {
        return RED      // 危险
    }
    if usedRatio > 0.70 || concentration > 0.35 {
        return YELLOW   // 注意
    }
    return GREEN        // 正常
}
```

**集中度计算（HHI - Herfindahl-Hirschman Index）：**

```go
// 计算 Top-N 目录的空间集中度
// HHI = sum(share_i^2)，范围 [1/N, 1]，越高越集中
func computeConcentration(entries []DirEntry, totalUsed int64) float64 {
    hhi := 0.0
    for _, e := range entries {
        share := float64(e.SizeBytes) / float64(totalUsed)
        hhi += share * share
    }
    return hhi
}
```

**综合风险评分：**

```go
// risk_pct = min(100, used_ratio * 60 + concentration * 40)
// 已用比例权重 60%，集中度权重 40%
func riskScore(usedRatio, concentration float64) float64 {
    return math.Min(100, usedRatio*60 + concentration*40)
}
```

**JSON 输出（与 CFPAI 对称）：**

```json
{
  "signal": {
    "light": "yellow",
    "risk_pct": 52.3,
    "used_pct": 72.0,
    "concentration_pct": 28.5,
    "free_budget_pct": 150.0,
    "description": "空间趋紧。D 盘 BaiduNetdiskDownload 占总用量 9.3%，建议检查。",
    "action": "运行 distrike hunt D:\\ 查看可清理项目。"
  }
}
```

**灯号与原斩杀线的关系：**

灯号系统是斩杀线的**升级版**，提供更细粒度的状态。原来的三级（SAFE/WARNING/CRITICAL）映射为：
- SAFE → GREEN
- WARNING → YELLOW
- CRITICAL → RED 或 PURPLE（取决于集中度和预算）

斩杀线仍然保留作为 PURPLE 判定的关键阈值（`free < kill_line`）。

### 2.2 猎物 (Prey)

被识别为可清理的空间占用项。每个猎物有：
- **路径** (path)
- **大小** (size)
- **类型** (kind): cache / temp / vdisk / backup / download / orphan / log
- **风险等级** (risk): safe / caution / danger
- **清理命令** (action): 具体的清理命令或操作说明
- **平台** (platform): windows / macos / linux / wsl
- **最后访问时间** (last_access)
- **描述** (description): 人类可读的说明

### 2.3 过滤清单 (Filter List)

用户可配置的规则文件，定义：
- **已知猎物模式** (known_prey): 自动识别的缓存/临时文件模式
- **白名单** (whitelist): 永远不标记为猎物的路径
- **自定义规则** (custom_rules): 用户定义的检测规则
- **平台条件** (platform_filter): 仅在特定平台生效的规则

---

## 3. 功能设计

### 3.1 子命令

```
distrike scan [path...]          扫描磁盘/目录，输出空间大户
distrike hunt [path...]          猎杀模式：扫描 + 识别猎物 + 给出清理建议
distrike status                  快速查看各盘/挂载点斩杀线状态
distrike clean [--dry-run]       执行清理（需确认）
distrike config                  查看/编辑配置
distrike history                 查看历史清理记录
distrike wsl                     WSL 发行版空间管理（Windows only）
```

### 3.2 scan — 空间扫描

```bash
# Windows
distrike scan D:\ --top 20
distrike scan C:\ D:\ --min-size 1G --json

# macOS
distrike scan /Users ~/Library --top 20

# Linux / WSL
distrike scan / /home --top 20

# 通用
distrike scan --all              # 扫描所有挂载点/盘符
distrike scan . --depth 3        # 当前目录，3层深度
```

**输出示例（人类模式）：**
```
D:\ (954 GB total, 30 GB free) [WARNING: 接近斩杀线 20 GB]

   92.0 GB  BaiduNetdiskDownload/        download
   85.0 GB  MobileSync/                  backup
   33.0 GB  LDPlayer/                    vdisk
    8.6 GB  Docker/                      vdisk
   15.2 GB  SteamLibrary/                app
    ...

Top 10 占总用量的 78.3%
扫描耗时: 2.3s (fastwalk)  |  缓存已保存
```

**JSON 输出（Agent 模式）：**
```json
{
  "drive": "D:\\",
  "total_bytes": 1024209543168,
  "free_bytes": 32212254720,
  "used_bytes": 991997288448,
  "kill_line_bytes": 21474836480,
  "status": "WARNING",
  "scan_duration_ms": 2300,
  "scan_engine": "fastwalk",
  "entries": [
    {
      "path": "D:\\BaiduNetdiskDownload",
      "size_bytes": 98784247808,
      "kind": "download",
      "last_modified": "2026-04-10T15:30:00Z",
      "children_count": 156
    }
  ]
}
```

### 3.3 hunt — 猎杀模式

在 scan 基础上，自动识别猎物并给出清理建议。

```bash
distrike hunt C:\                # 猎杀 C 盘
distrike hunt --all              # 猎杀所有盘/挂载点
distrike hunt --risk safe        # 只看安全可清理的
distrike hunt --json             # JSON 输出
distrike hunt ~/Library          # macOS Library 猎杀
```

**输出示例：**
```
C:\ (454 GB total, 3.8 GB free) [CRITICAL: 低于斩杀线 20 GB!]

猎物清单:
  [SAFE]    2.4 GB  pip cache              AppData\Local\pip\cache
            清理: pip cache purge
  [SAFE]    373 MB  npm cache              AppData\Local\npm-cache
            清理: npm cache clean --force
  [SAFE]    1.2 GB  Windows Temp           AppData\Local\Temp
            清理: 清除临时文件
  [CAUTION] 4.1 GB  Docker VHDX            Docker\DockerDesktopWSL
            清理: docker system prune + diskpart compact
  [DANGER]  85 GB   iPhone Backup          MobileSync\Backup
            清理: 手动确认后删除旧备份

可安全回收: 3.97 GB | 需确认: 4.1 GB | 高风险: 85 GB
距离脱离斩杀线还需清理: 16.2 GB
```

**JSON 输出（Agent 友好）：**
```json
{
  "drive": "C:\\",
  "status": "CRITICAL",
  "free_bytes": 4080218931,
  "kill_line_bytes": 21474836480,
  "deficit_bytes": 17394617549,
  "prey": [
    {
      "path": "C:\\Users\\asus\\AppData\\Local\\pip\\cache",
      "size_bytes": 2576980378,
      "kind": "cache",
      "risk": "safe",
      "platform": "windows",
      "description": "Python pip package download cache",
      "action": {
        "command": "pip cache purge",
        "type": "command",
        "shell": "default"
      },
      "last_access": "2026-04-14T12:00:00Z"
    }
  ],
  "summary": {
    "safe_bytes": 4264509440,
    "caution_bytes": 4402341478,
    "danger_bytes": 91268055040,
    "deficit_bytes": 17394617549
  }
}
```

### 3.4 status — 斩杀线状态

```bash
distrike status          # 所有盘/挂载点
distrike status --json   # Agent 模式
```

**Windows 输出：**
```
C:\  [████████████████████░]  3.8 GB / 454 GB  CRITICAL
D:\  [████████████████░░░░░]   30 GB / 954 GB  WARNING

WSL Distributions:
  Ubuntu-22.04  ext4.vhdx  12.3 GB  (sparse: off)
  docker-data   VHDX        8.6 GB

斩杀线: 20 GB
```

**macOS 输出：**
```
/          [███████████████░░░░░]   45 GB / 500 GB  SAFE
/Volumes/Data  [██████████████████░░]   22 GB / 200 GB  WARNING

斩杀线: 20 GB
```

### 3.5 clean — 执行清理

```bash
distrike clean --dry-run                    # 预览
distrike clean --risk safe                  # 只清安全项
distrike clean --target "pip cache"         # 清指定猎物
distrike clean --risk safe --yes --json     # Agent 静默模式
```

### 3.6 config — 配置管理

```bash
distrike config show
distrike config set kill-line 20G
distrike config whitelist add "D:\GenshinImpact_4.0.1"
distrike config rule add --path "*.vmdk" --kind vdisk --risk caution
```

### 3.7 wsl — WSL 发行版管理（Windows only）

```bash
distrike wsl list                           # 列出所有发行版 + VHDX 大小
distrike wsl compact Ubuntu-22.04           # fstrim + diskpart compact
distrike wsl hunt Ubuntu-22.04              # 扫描发行版内部猎物
distrike wsl clean Ubuntu-22.04 --risk safe # 清理发行版内部缓存
```

---

## 4. 跨平台猎物识别规则

### 4.1 通用缓存类 (cache) — 默认 SAFE

| 模式 | 平台 | 说明 | 清理命令 |
|------|------|------|----------|
| `*/pip/cache` | ALL | Python pip 缓存 | `pip cache purge` |
| `*/npm-cache` / `*/.npm` | ALL | npm 缓存 | `npm cache clean --force` |
| `*/yarn/cache` | ALL | yarn 缓存 | `yarn cache clean` |
| `*/pnpm/store` | ALL | pnpm 缓存 | `pnpm store prune` |
| `*/.cache/go-build` | ALL | Go 编译缓存 | `go clean -cache` |
| `*/.cargo/registry` | ALL | Rust crate 缓存 | `cargo cache --autoclean` |
| `*/.gradle/caches` | ALL | Gradle 缓存 | 手动删除 |
| `*/.nuget/packages` | ALL | NuGet 缓存 | `dotnet nuget locals all --clear` |
| `*/torch/hub` | ALL | PyTorch 模型缓存 | 手动删除 |
| `*/huggingface/hub` | ALL | HuggingFace 模型缓存 | `huggingface-cli delete-cache` |
| `*/conda/pkgs` | ALL | conda 包缓存 | `conda clean --all` |

### 4.2 Windows 专属

| 模式 | 说明 | 清理命令 |
|------|------|----------|
| `*/AppData/Local/Temp` | 用户临时文件 | 删除内容 |
| `*/Windows/Temp` | 系统临时文件 | 需要 Admin |
| `*/$RECYCLE.BIN` | 回收站 | 清空回收站 |
| `*/AppData/Local/CrashDumps` | 崩溃转储 | 删除 |
| `*/AppData/Local/D3DSCache` | DirectX 着色器缓存 | 删除 |
| `*/cygwin64/var/cache/setup` | Cygwin 包缓存 | 删除 |

### 4.3 macOS 专属

| 模式 | 说明 | 清理命令 |
|------|------|----------|
| `~/Library/Developer/Xcode/DerivedData` | Xcode 编译缓存 | `rm -rf` (80-200+ GB!) |
| `~/Library/Developer/Xcode/iOS DeviceSupport` | iOS 设备支持 | 删除旧版本 |
| `~/Library/Caches/Homebrew` | Homebrew 缓存 | `brew cleanup --prune=all` |
| `~/Library/Caches` | 应用缓存 | 按应用选择性删除 |
| `~/Library/Application Support/MobileSync/Backup` | iPhone 备份 | 手动确认 |
| Time Machine local snapshots | 本地快照 | `tmutil deletelocalsnapshots` |
| Simulator runtimes | 模拟器 | `xcrun simctl delete unavailable` |

### 4.4 Linux / WSL 专属

| 模式 | 说明 | 清理命令 |
|------|------|----------|
| `/var/cache/apt` | apt 包缓存 | `sudo apt clean` |
| `/var/log` (>500MB) | 系统日志 | `sudo journalctl --vacuum-time=7d` |
| `/var/lib/snapd` | snap 数据 | `sudo snap remove --purge <unused>` |
| `~/.cache` | 用户缓存 | 按内容选择性删除 |
| `*.gz` in `/var/log` | 压缩旧日志 | `sudo find /var/log -name '*.gz' -delete` |
| orphan packages | 孤立包 | `sudo apt autoremove -y` |

### 4.5 虚拟磁盘类 (vdisk) — 默认 CAUTION

| 模式 | 平台 | 说明 | 清理方式 |
|------|------|------|----------|
| `*.vhdx` | Windows | WSL / Docker / Hyper-V | `fstrim -av` + `diskpart compact` |
| `*.vmdk` | ALL | VMware / LDPlayer | `vmware-vdiskmanager -k` |
| `*.vdi` | ALL | VirtualBox | `VBoxManage modifymedium --compact` |
| `*.qcow2` | Linux/macOS | QEMU | `qemu-img convert` |
| `Docker.raw` | macOS | Docker Desktop | `docker system prune` + 重建 |

### 4.6 备份类 (backup) — 默认 CAUTION

| 模式 | 平台 | 说明 |
|------|------|------|
| `*/MobileSync/Backup` | Win/Mac | iPhone 备份 |
| `*/WindowsImageBackup` | Windows | 系统镜像备份 |
| Time Machine snapshots | macOS | 本地时间机器快照 |

### 4.7 下载类 (download) — 默认 CAUTION

| 模式 | 说明 |
|------|------|
| `*/Downloads` | 用户下载文件夹 |
| `*/BaiduNetdiskDownload` | 百度网盘下载 |
| `*/Thunder` | 迅雷下载 |

### 4.8 孤儿类 (orphan) — 默认 CAUTION

运行时检测：
- Docker 悬空镜像/停止容器/未使用卷
- 已卸载软件的残留数据目录
- WSL 中未使用的 snap 包

---

## 5. Agent 友好设计

### 5.1 设计原则

1. **结构化输出**: 所有命令支持 `--json`，schema 稳定且有版本
2. **明确退出码**: 0=SAFE, 1=有WARNING/CRITICAL盘, 2=执行错误
3. **无交互模式**: `--yes` 跳过确认，`--quiet` 减少输出
4. **管道友好**: stdout 输出结果，stderr 输出进度/日志
5. **幂等操作**: 重复执行 clean 不会出错
6. **机器可读 action**: 猎物的 action 包含可直接执行的命令 + shell 类型
7. **平台感知**: action.command 根据当前平台返回正确的命令

### 5.2 Agent 典型工作流

```bash
# 1. Agent 检查斩杀线状态
distrike status --json

# 2. 如果 CRITICAL，执行猎杀
distrike hunt C:\ --json

# 3. 解析 JSON，筛选 safe 猎物
# 4. 执行清理
distrike clean --risk safe --yes --json

# 5. 再次检查状态
distrike status --json
```

### 5.3 Claude Code 集成

```python
# Agent 可以直接：
result = bash("distrike hunt --all --json")
data = json.loads(result)

for drive in data["drives"]:
    if drive["status"] == "CRITICAL":
        for prey in drive["prey"]:
            if prey["risk"] == "safe":
                bash(prey["action"]["command"])
```

### 5.4 JSON Schema 版本控制

```json
{
  "schema_version": "1.0",
  "tool": "distrike",
  "tool_version": "0.1.0",
  "timestamp": "2026-04-14T14:30:00Z",
  "platform": "windows",
  ...
}
```

---

## 6. 配置文件

默认位置：
- Windows: `%APPDATA%\distrike\config.yaml`
- macOS: `~/Library/Application Support/distrike/config.yaml`
- Linux: `~/.config/distrike/config.yaml`

```yaml
# 斩杀线配置
kill_line: 20GB

# 扫描设置
scan:
  max_depth: 3
  min_size: 100MB
  top: 20
  follow_symlinks: false
  engine: auto          # auto / fastwalk / mft (Windows Admin only)
  cache: true           # 启用 SQLite 扫描缓存
  cache_ttl: 1h         # 缓存过期时间

# 白名单
whitelist:
  - "D:\\GenshinImpact_4.0.1"
  - "D:\\Star Rail"
  - "~/important-project"

# 自定义猎物规则
custom_rules:
  - pattern: "*/LDPlayer/*/vms/*/data.vmdk"
    kind: vdisk
    risk: caution
    platform: windows
    description: "雷电模拟器虚拟磁盘"
    action:
      type: manual
      hint: "使用 ShrinkLDPlayer 工具压缩"

# Docker 集成
docker:
  enabled: true
  # 自动检测 docker executable

# WSL 集成（Windows only）
wsl:
  enabled: true
  auto_compact: false   # 自动压缩 VHDX

# 历史记录
history:
  enabled: true
  max_entries: 100
  path: auto            # 默认存配置目录下
```

---

## 7. 技术架构

### 7.0 语言选型结论

**Go**，经 Tree Diagram + HCE 联合评估确认。

#### Tree Diagram 数值分析

使用 treesea/tree_diagram 的 ProblemSeed 模型对 Distrike 项目特征建模，quick profile 运行结果：
- **batch 家族 100% 霸榜**（Top 12 全部为 batch_route）
- 含义：I/O 吞吐型任务，低风险，不需要 phase/network 级复杂度
- feasibility=0.87（高）、stability=0.69（中高）、risk=0.30（低）、utm=FLOOD（资源充裕）

#### HCE 选型框架验证

应用 treesea/HCE 技术栈选型文档的核心原则——**"选择基于当前阶段约束，而非语言抽象能力"**：

| HCE 判据 | Distrike 情况 | 结论 |
|----------|-------------|------|
| 有无 legacy 需迁移？ | 无，全新项目 | 不排除任何语言 |
| 核心是编排层还是数值核？ | CLI 编排 + I/O 扫描 | Go 最优区间 |
| 是否需要极限 CPU 性能？ | 否，瓶颈是磁盘 I/O | Rust 优势用不上 |
| 开发者经验？ | Go 熟练 (cygctl) | Go 开发速度最快 |
| 是否需要与现有生态集成？ | 是，cygctl (Go) | Go 直接复用 |
| 交叉编译需求？ | 三平台 | Go 一行搞定 |

#### 加权评分

| 维度 | Go | Rust | Zig | 权重 |
|------|-----|------|-----|------|
| 开发速度 | 0.95 | 0.60 | 0.50 | 0.30 |
| 运行性能 | 0.82 | 0.95 | 0.90 | 0.15 |
| 生态成熟度 | 0.90 | 0.80 | 0.45 | 0.20 |
| 交叉编译 | 0.95 | 0.75 | 0.85 | 0.10 |
| MFT 库可用性 | 0.85 | 0.90 | 0.20 | 0.10 |
| cygctl 集成 | 1.00 | 0.10 | 0.10 | 0.10 |
| Agent 友好 | 0.90 | 0.85 | 0.70 | 0.05 |
| **加权总分** | **0.917** | **0.709** | **0.514** | |
| **risk** | **0.12** | **0.35** | **0.55** | |

**Go 以 0.917 分胜出。** 两个系统独立运算，结论收敛。

### 7.1 语言与依赖

- **语言**: Go 1.22+
- **编译目标**: Windows (amd64/arm64), macOS (amd64/arm64), Linux (amd64/arm64)
- **零外部依赖运行**: 编译为单文件可执行文件
- **构建依赖**:

| 库 | 用途 |
|---|---|
| `github.com/spf13/cobra` | CLI 框架（与 cygctl 一致） |
| `gopkg.in/yaml.v3` | 配置文件 |
| `golang.org/x/sys/windows` | Windows API（GetDiskFreeSpaceEx, Registry） |
| `golang.org/x/sys/unix` | POSIX Statfs |
| `github.com/charlievieth/fastwalk` | 并发目录遍历，比 stdlib 快 6x |
| `github.com/shirou/gopsutil/v3/disk` | 跨平台磁盘信息 |
| `github.com/Velocidex/go-ntfs` | NTFS MFT 直读（可选，Admin 模式） |
| `modernc.org/sqlite` | 扫描缓存（纯 Go，无 CGO） |

### 7.2 模块结构

```
distrike/
├── cmd/                        # CLI 命令定义 (cobra)
│   ├── root.go                # 根命令 + 全局 flags
│   ├── scan.go                # scan 子命令
│   ├── hunt.go                # hunt 子命令
│   ├── status.go              # status 子命令
│   ├── clean.go               # clean 子命令
│   ├── config.go              # config 子命令
│   └── wsl.go                 # wsl 子命令 (Windows only)
├── scanner/                    # 磁盘扫描引擎
│   ├── engine.go              # 扫描引擎接口
│   ├── fastwalk.go            # fastwalk 并发遍历（默认）
│   ├── mft.go                 # NTFS MFT 直读（Windows Admin）
│   ├── entry.go               # 文件/目录条目
│   ├── topn.go                # Top-N min-heap
│   └── cache.go               # SQLite 扫描缓存
├── hunter/                     # 猎物识别引擎
│   ├── rules.go               # 内建规则注册
│   ├── rules_windows.go       # Windows 专属规则
│   ├── rules_darwin.go        # macOS 专属规则
│   ├── rules_linux.go         # Linux/WSL 专属规则
│   ├── rules_common.go        # 通用规则
│   ├── matcher.go             # 模式匹配引擎
│   ├── prey.go                # 猎物数据结构
│   ├── docker.go              # Docker 集成检测
│   └── vdisk.go               # 虚拟磁盘检测
├── killline/                   # 斩杀线逻辑
│   ├── status.go              # 状态判定
│   ├── drive_windows.go       # Windows 盘符枚举
│   ├── drive_darwin.go        # macOS 挂载点
│   └── drive_unix.go          # Linux 挂载点
├── wsl/                        # WSL 管理 (Windows only)
│   ├── distro.go              # 发行版枚举（Registry）
│   ├── vhdx.go                # VHDX 大小/压缩
│   └── internal.go            # WSL 内部扫描
├── cleaner/                    # 清理执行器
│   ├── executor.go            # 命令执行
│   ├── history.go             # 历史记录
│   └── dryrun.go              # 预览模式
├── output/                     # 输出格式化
│   ├── json.go                # JSON 输出 + schema version
│   ├── text.go                # 人类可读输出
│   └── progress.go            # 进度条 (stderr)
├── config/                     # 配置管理
│   ├── config.go              # 配置结构 + 加载
│   ├── defaults.go            # 默认值
│   └── paths.go               # 跨平台配置路径
├── main.go
├── go.mod
├── go.sum
├── Makefile
├── .goreleaser.yaml            # 跨平台发布
├── README.md
└── distrike.yaml.example
```

### 7.3 扫描引擎分级

```
┌──────────────────────────────────────────────────────────┐
│              Scan Engine Selection                         │
│                                                            │
│  engine=auto (默认)                                        │
│      │                                                     │
│      ├── Windows + Admin + NTFS?                           │
│      │    └── YES → MFT 直读 (18秒/454GB 实测)            │
│      │         自定义二进制 MFT 解析器                     │
│      │         go-ntfs 仅用于 bootstrap 定位 $MFT          │
│      │                                                     │
│      ├── 有 SQLite 缓存且未过期?                            │
│      │    └── YES → 缓存读取 (瞬间)                        │
│      │                                                     │
│      └── 默认 → fastwalk 并发遍历                          │
│           charlievieth/fastwalk + HDD/SSD 自动检测         │
│           SSD: GOMAXPROCS×2 workers / HDD: 1 worker        │
│                                                            │
│  进度输出 → stderr (不污染 JSON stdout)                    │
└──────────────────────────────────────────────────────────┘
```

**速度实测（454GB NTFS SSD，2.2M MFT 记录）：**

| 引擎 | 速度 | 要求 |
|------|------|------|
| MFT 直读 | **18 秒** | Windows Admin + NTFS |
| SQLite 缓存 | 瞬间 | 有未过期缓存 |
| fastwalk | 14-31 秒 | 通用 |

### 7.4 MFT 引擎架构（Möbius Ring + OPU Batch I/O）

MFT 引擎不使用 go-ntfs 的 `ParseMFTFile`（太慢：完整属性解析 20+ 字段），而是自定义二进制解析器只提取 4 个字段。

**三遍 Möbius 环流水线：**

```
Pass 1: OPU 批量 I/O + 并行解析
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐
│  Producer    │    │  Worker Pool     │    │  Node Map    │
│  (single)    │───→│  (N goroutines)  │───→│  (merge)     │
│              │    │                  │    │              │
│  ReadAt 1MB  │    │  parseMFTRecord  │    │  2M+ nodes   │
│  (1024 rec)  │    │  applyFixup      │    │              │
│  batch read  │    │  4 fields only   │    │              │
└─────────────┘    └──────────────────┘    └──────────────┘
     OPU-style                                    │
     prefetch                                     ▼
     coalescing                        Pass 1.5: Ring Buffer
                                       ┌──────────────────┐
                                       │  Sort by entryID  │
                                       │  2MB ring window  │
                                       │  sequential I/O   │
                                       │  14330/14895 解析 │
                                       └────────┬─────────┘
                                                │
                                       Pass 1.5b: Möbius Twist
                                       ┌──────────────────┐
                                       │  仅 15 个 owner  │
                                       │  (非 31K 空叶)    │
                                       │  chase data runs  │
                                       │  non-resident AL  │
                                       └────────┬─────────┘
                                                │
                                                ▼
                                       Phase 2: 目录树链接
                                       ┌──────────────────┐
                                       │  parent-child     │
                                       │  保留 metafile    │
                                       │  (Möbius 交界面)  │
                                       └────────┬─────────┘
                                                │
                                                ▼
                                       Phase 3: 拓扑排序
                                       ┌──────────────────┐
                                       │  叶→根累积 size   │
                                       │  Kahn's algorithm │
                                       └──────────────────┘
```

**性能分解（454GB NTFS 实测）：**

| 阶段 | 耗时 | 说明 |
|------|-----:|------|
| Phase 1 读取+解析 | 10.3s | 1MB 批量 I/O + N-worker 并行解析 |
| Phase 1.5 Ring + Möbius | 5.0s | 排序后顺序读 + 15 个目标 Möbius |
| Phase 2 目录树链接 | 0.7s | 200 万节点 parent-child |
| Phase 3 累积大小 | 2.1s | 拓扑排序 bottom-up 传播 |
| **总计** | **18.3s** | |

**关键优化：**

1. **OPU 批量预取**（借鉴 treesea/OPU FrictionPolicy）：每次 ReadAt 读 1MB（1024 条记录），而非逐条 1KB。I/O 系统调用减少 1000 倍。

2. **自定义 MFT 解析器**：直接从 1KB 二进制记录提取 `$FILE_NAME`（文件名+父 FRN）和 `$DATA`（文件大小），跳过 go-ntfs 的完整属性枚举（时间戳×8、ADS、flags、logfile seq 等 20+ 无用字段）。

3. **NTFS Fixup**：应用 update sequence array 还原扇区边界字节，否则属性数据被 USN 值污染导致 TB 级溢出。

4. **Möbius 环 $ATTRIBUTE_LIST 解析**：
   - 正面（resident）：直接解析 attribute list 获取外部 `$DATA` 引用
   - 反面（non-resident）：解码 NTFS data runs → 读取 attribute list 内容 → 解析引用
   - 交界面：目录树本身——不删除任何节点（包括 metafile），保持 Möbius 环连续性
   - 叶节点集中度优化：只处理 15 个真正未解析的 owner，不遍历 31K+ 空叶子

5. **Ring Buffer 顺序化**：将 14895 个随机外部引用按 entry number 排序，用 2MB 滑动窗口顺序读取，将随机 I/O 转化为顺序 I/O。

6. **sectorAlignedReader**：Windows raw volume 要求读取大小为 512 字节的整数倍，包装层自动对齐。

**可见内核文件**：MFT 引擎能看到 `hiberfil.sys`、`pagefile.sys`、`swapfile.sys` 等被内核锁定的文件——因为读的是磁盘扇区而非文件句柄。

### 7.5 引擎对比基准测试

实测环境：454 GB NTFS SSD，2.2M 文件，Windows 10

| 维度 | fastwalk | MFT | 说明 |
|------|---------|-----|------|
| **时间（正常负载）** | **14.7s** | **18.3s** | fastwalk 略快 |
| **时间（高负载）** | 33.2s | 39.0s | 系统卡顿时均受影响 |
| C:\Users | 238.4 GB | 208.0 GB | fastwalk 含 hardlink 重复计算 |
| C:\Windows | 40.4 GB | 35.7 GB | WinSxS hardlinks 差异 |
| C:\Program Files | 55.8 GB | 68.5 GB | MFT 含隐藏/系统文件 |
| C:\ProgramData | 19.7 GB | 19.7 GB | 完美匹配 |
| hiberfil.sys | 不可见 | **可见 (9.5 GB)** | MFT 独占优势 |
| pagefile.sys | 不可见 | **可见 (2.3 GB)** | MFT 独占优势 |
| 需要 Admin | 否 | 是 | |
| 跨平台 | 是 | 仅 Windows NTFS | |
| 大小语义 | 逻辑占用（含 hardlink） | 物理占用（去重） | 两种都正确 |

**选择策略**：`engine=auto` 时，Admin + NTFS 自动用 MFT（能看到更多），否则用 fastwalk（无需权限）。用户也可 `--engine fastwalk` 或 `--engine mft` 强制指定。

### 7.6 跨平台验证

**编译测试**：Go 交叉编译，单一代码库产出三平台二进制。

```bash
# Windows (原生)
go build -o distrike.exe .       # 12 MB

# Linux (交叉编译)
GOOS=linux GOARCH=amd64 go build -o distrike_linux .

# macOS (交叉编译)
GOOS=darwin GOARCH=arm64 go build -o distrike_darwin .
```

**实测结果（2026-04-15）**：

| 测试 | 平台 | 命令 | 结果 |
|------|------|------|------|
| Windows exe → Windows | Win10 | `distrike.exe status` | 4 盘显示，灯号正确 |
| Windows exe → WSL (interop) | WSL2 | `wsl -- distrike.exe status` | 看到 Windows 盘（通过 WSL interop） |
| Linux binary → WSL (原生) | WSL2 Ubuntu 22.04 | `./distrike_linux status` | 看到 Linux 挂载点（/、/snap 等） |
| hunt --after 3d | Win10 | `distrike.exe hunt C: --after 3d` | 21 猎物 5.7 GB（时间过滤生效） |
| watch 自适应 | Win10 | `distrike.exe watch` | PURPLE 10s / RED 30s / YELLOW 5m / GREEN 15m |
| watch --install | Win10 | `distrike.exe watch --install` | schtasks 注册成功 |

**平台差异**：
- Windows：status 显示盘符（C:\、D:\），MFT 引擎可用
- Linux/WSL：status 显示挂载点（/、/snap），MFT 不可用（非 NTFS），自动降级到 fastwalk
- macOS：status 显示 APFS 卷，fastwalk 引擎

### 7.7 扫描缓存（借鉴 gdu）

使用 `modernc.org/sqlite`（纯 Go SQLite，无 CGO）：

```sql
CREATE TABLE scan_cache (
    path TEXT PRIMARY KEY,
    size_bytes INTEGER,
    children INTEGER,
    kind TEXT,
    last_modified INTEGER,
    scan_time INTEGER
);

CREATE INDEX idx_size ON scan_cache(size_bytes DESC);
```

- 每次扫描后自动保存
- 再次打开同一路径时秒开（<100ms）
- 可配置 TTL（默认 1 小时）
- `distrike scan --no-cache` 强制重新扫描

### 7.6 HDD/SSD 自动检测（借鉴 gdu）

```go
// Windows: WMI 查询 MediaType
// Linux: /sys/block/<dev>/queue/rotational (0=SSD, 1=HDD)
// macOS: diskutil info -plist

if isHDD(path) {
    // 串行遍历，避免 seek 惩罚
    workerCount = 1
} else {
    // SSD 并发遍历
    workerCount = runtime.GOMAXPROCS(0) * 2
}
```

### 7.7 与 Tensorearch 的架构对称

| Tensorearch | Distrike | 对应关系 |
|-------------|----------|----------|
| SystemTrace | DriveInfo | 系统级元数据 |
| SliceState | DirEntry | 节点/条目 |
| SliceEdge | ParentChild | 边/层级关系 |
| ArchitectureGraph | DiskGraph | 拓扑图 |
| base_cost() | entry_size() | 节点代价 |
| topological_congestion() | space_pressure() | 拓扑压力 |
| DiagnosticItem | Prey | 诊断/猎物 |
| inspect report | hunt report | 检查报告 |

---

## 8. 加密磁盘、权限与存储健康

### 8.1 加密磁盘处理

| 场景 | 检测方式 | 处理 |
|------|----------|------|
| BitLocker (Windows) | `manage-bde -status` 或 WMI `Win32_EncryptableVolume` | 已解锁：正常扫描；锁定中：报告状态，跳过扫描 |
| FileVault (macOS) | `fdesetup status` 或 `diskutil apfs list` | APFS 加密透明，已登录即可扫描；报告加密状态 |
| LUKS (Linux) | `/proc/crypto` + `lsblk -o NAME,FSTYPE,TYPE` 检查 `crypt` | 已挂载：正常扫描；未挂载：跳过 |
| VeraCrypt 容器 | 扫描 `.hc` / `.tc` 文件 | 标记为 vdisk 类型，报告大小，不尝试打开 |

**灯号集成：** 加密但锁定的磁盘不参与灯号计算，但在 status 输出中标注 `[ENCRYPTED-LOCKED]`。

### 8.2 权限不足处理

扫描过程中遇到权限拒绝时的处理策略：

```go
type AccessDeniedPolicy int
const (
    Skip    AccessDeniedPolicy = iota  // 跳过并记录（默认）
    Warn                                // 跳过并警告
    Elevate                             // 提示用户提权重试
)
```

| 场景 | 平台 | 处理 |
|------|------|------|
| `Access is denied` | Windows | 记录路径，汇报跳过数量和预估丢失大小 |
| `Operation not permitted` | macOS (SIP) | 标记 `[SIP-PROTECTED]`，报告但不清理 |
| `Permission denied` | Linux | 提示 `sudo distrike scan` |
| 部分目录不可读 | ALL | 输出中标注 `scanned: 95%` + `denied_paths: [...]` |

**JSON 输出中的权限信息：**

```json
{
  "scan_coverage": 0.95,
  "denied_paths": [
    {"path": "C:\\System Volume Information", "error": "access denied"},
    {"path": "/var/db/oah", "error": "operation not permitted (SIP)"}
  ],
  "denied_estimated_bytes": 1073741824,
  "encryption_status": [
    {"drive": "C:\\", "method": "BitLocker", "state": "unlocked"},
    {"drive": "E:\\", "method": "BitLocker", "state": "locked", "skipped": true}
  ]
}
```

**Agent 行为：** 当 `scan_coverage < 0.8` 时，JSON 输出增加 `"warning": "扫描覆盖率低于 80%，结果可能不准确，建议以管理员权限重新扫描"`。

### 8.3 存储健康检测

针对可移动存储（U 盘、SD 卡、移动硬盘）和老化磁盘的异常检测。

**检测项目：**

| 检测 | 方法 | 适用 | 灯号影响 |
|------|------|------|----------|
| 容量异常 | 标称容量 vs 实际可用差距 > 10% | U 盘/SD 卡 | YELLOW（可能是山寨盘） |
| SMART 状态 | WMI `Win32_DiskDrive` / `smartctl` | HDD/SSD | RED（SMART 报警时） |
| 坏道检测 | SMART `Reallocated_Sector_Ct` / `Current_Pending_Sector` | HDD | RED（坏道增长） |
| 文件系统错误 | `chkdsk` 状态 / `fsck` 日志 | ALL | YELLOW |
| 写入寿命 | SMART `Wear_Leveling_Count` / `Media_Wearout_Indicator` | SSD/U盘 | YELLOW（<20% 寿命） |

**容量异常检测（山寨 U 盘识别）：**

```go
// 检测容量欺诈：标称 vs 实际
func detectCapacityAnomaly(device StorageDevice) *HealthAlert {
    if !device.IsRemovable {
        return nil  // 只检测可移动设备
    }
    // 标称容量（分区表报告）vs 文件系统实际可用
    ratio := float64(device.FSAvailable+device.FSUsed) / float64(device.PartitionSize)
    if ratio < 0.90 {
        return &HealthAlert{
            Level:   "yellow",
            Kind:    "capacity_anomaly",
            Message: fmt.Sprintf("容量异常：标称 %s，实际可用 %s（%.0f%%），可能是山寨存储设备",
                humanSize(device.PartitionSize),
                humanSize(device.FSAvailable+device.FSUsed),
                ratio*100),
        }
    }
    return nil
}
```

**SMART 健康检查：**

```go
// Windows: WMI Win32_DiskDrive.Status
// Linux: smartctl -H /dev/sdX
// macOS: smartctl -H /dev/diskN (需要安装 smartmontools)
func checkSMARTHealth(device StorageDevice) *HealthAlert {
    if device.SMARTStatus == "OK" || device.SMARTStatus == "PASSED" {
        return nil
    }
    return &HealthAlert{
        Level:   "red",
        Kind:    "smart_warning",
        Message: fmt.Sprintf("SMART 报警：%s 状态为 %s，建议立即备份数据",
            device.Path, device.SMARTStatus),
    }
}
```

**JSON 输出：**

```json
{
  "health": [
    {
      "device": "E:\\",
      "type": "usb",
      "model": "SanDisk Ultra",
      "alerts": [
        {
          "level": "yellow",
          "kind": "capacity_anomaly",
          "message": "容量异常：标称 128 GB，实际可用 115 GB（89.8%）"
        }
      ],
      "smart": {
        "status": "PASSED",
        "reallocated_sectors": 0,
        "pending_sectors": 0,
        "wear_level_pct": 95
      }
    }
  ]
}
```

**灯号集成：**

存储健康异常会影响整体灯号：
- SMART 报警 → 该设备灯号强制 RED（不管空间多充裕）
- 容量异常 → YELLOW
- 坏道增长 → RED
- 这些异常叠加到 `distrike status` 的整体灯号输出中

**适用范围：**

| 设备类型 | 容量异常 | SMART | 坏道 | 寿命 |
|----------|----------|-------|------|------|
| 内置 SSD | - | 检测 | - | 检测 |
| 内置 HDD | - | 检测 | 检测 | - |
| U 盘 | 检测 | 有限 | - | 有限 |
| SD 卡 | 检测 | - | - | - |
| 移动硬盘 | - | 检测 | 检测 | - |
| 网络存储 | - | - | - | - |

---

## 9. 跨平台注意事项

### 9.1 macOS 特殊处理

| 问题 | 处理 |
|------|------|
| SIP 保护路径 (`/System`, `/usr`) | 报告大小但标记为不可清理 |
| APFS clone/snapshot 去重 | `du` 报告的大小可能偏大，标注 "APFS apparent size" |
| APFS purgeable space | Finder 显示的可用空间 > `df`，使用 `diskutil info` 获取真实值 |
| Full Disk Access 权限 | 提示用户授权，否则部分 `~/Library` 不可读 |
| Rosetta 缓存 (`/var/db/oah/`) | SIP 保护，报告但不清理 |

### 9.2 WSL 特殊处理

| 问题 | 处理 |
|------|------|
| VHDX 只增不缩 | `distrike wsl compact` 自动执行 fstrim + diskpart |
| 从 Windows 侧检测发行版 | 读 Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` |
| WSL 内部扫描 | `wsl -d <distro> -- distrike hunt /` |
| Sparse VHD 模式 (WSL 2.1+) | 检测并提示 `wsl --manage <d> --set-sparse true` |

### 9.3 Linux 特殊处理

| 问题 | 处理 |
|------|------|
| 伪文件系统 | 跳过 `/proc`, `/sys`, `/dev`, `/run` |
| btrfs subvolume | 检测 btrfs 并提示空间可能有快照占用 |
| snap 包 | 枚举并标记过期 snap revision |

### 9.4 Build Tags 组织

```go
// scanner/mft.go
//go:build windows

// wsl/distro.go
//go:build windows

// hunter/rules_darwin.go
//go:build darwin

// killline/drive_unix.go
//go:build linux || darwin
```

---

## 10. 开发阶段

### Phase 1: 核心扫描 + 斩杀线（MVP）— Windows 优先
- [ ] `distrike status` — 各盘剩余空间 + 斩杀线状态
- [ ] `distrike scan` — fastwalk 并发扫描 + Top-N
- [ ] `--json` 输出
- [ ] 基本配置文件 (YAML)
- [ ] 跨平台编译 (.goreleaser.yaml)

### Phase 2: 猎杀模式
- [ ] `distrike hunt` — 内建规则匹配
- [ ] Windows 缓存/临时/虚拟磁盘规则
- [ ] macOS 规则（Xcode, Homebrew, Library）
- [ ] Linux/WSL 规则（apt, journal, snap）
- [ ] 白名单 / 自定义规则
- [ ] 清理命令建议（跨平台 action）

### Phase 3: 清理执行 + 缓存
- [ ] `distrike clean` — 执行清理
- [ ] `--dry-run` 预览
- [ ] 历史记录
- [ ] Docker 集成
- [ ] SQLite 扫描缓存

### Phase 4: 高速引擎
- [ ] NTFS MFT 直读（Windows Admin）
- [ ] HDD/SSD 自动检测
- [ ] USN Journal 增量更新

### Phase 5: WSL + 虚拟磁盘
- [ ] `distrike wsl` — WSL 发行版管理
- [ ] VHDX 自动压缩
- [ ] VMDK/VDI 压缩集成
- [ ] Everything SDK 集成（可选）

### Phase 6: 容量反弹监控模式

**起因**：Distrike 开发者在 2026-04-14 手动清理了 33.7 GB 磁盘空间。三天后发现 C 盘又从 3.8 GB 剩余跌到接近 0。用 `distrike scan --after 3d` 追查发现 QQ 消息数据库 3 天内写入 15.6 GB，Claude Code VM 增长 9.3 GB，各种应用缓存持续膨胀——空间被"反弹"吃回去了。

**问题本质**：清理是一次性的，但应用写入是持续的。没有监控就不知道空间什么时候、被什么程序吃掉的。等到磁盘满了再查，已经来不及了。

**灵感来源**：杀毒软件的即时防护（real-time protection）。杀软通过 minifilter/fanotify 钩子监控文件写入检测恶意行为；Distrike 通过 USN Journal 监控文件写入检测容量反弹。hook 点相同，过滤逻辑不同。

**核心功能**：`distrike watch` — 容量反弹监控守护进程

```bash
# 启动监控（前台）
distrike watch C: --kill-line 20GB

# 后台守护
distrike watch --daemon --all

# 查看监控状态
distrike watch --status
```

**架构**：

```
USN Journal (FSCTL_READ_USN_JOURNAL)
    │
    │  实时流式读取文件变更记录
    ▼
┌─────────────────────────────────────┐
│  Watch Goroutine (持续运行)          │
│                                     │
│  for each USN record:               │
│    1. Bitset 检查: 已知文件?         │
│    2. 累积写入量 (sliding window)    │
│    3. 检查斩杀线距离                 │
│    4. 检查单文件暴涨 (>100MB/min)    │
│    5. 检查总写入速率                 │
└─────────┬───────────────────────────┘
          │
          ▼  触发条件满足时
┌─────────────────────────────────────┐
│  Alert System                       │
│                                     │
│  YELLOW: 写入速率异常               │
│  RED:    接近斩杀线 (<5GB)          │
│  PURPLE: 已跌破斩杀线              │
│                                     │
│  通知方式:                          │
│  - Windows: Toast notification      │
│  - macOS: osascript                 │
│  - Linux: notify-send               │
│  - 通用: stderr + JSON log          │
└─────────────────────────────────────┘
```

**告警规则**：

| 触发条件 | 灯号 | 动作 |
|----------|------|------|
| 单文件 10 分钟内增长 >500MB | YELLOW | 报告文件名和增长量 |
| 剩余空间 < kill_line × 1.5 | YELLOW | 建议运行 hunt |
| 剩余空间 < kill_line | RED | 自动运行 hunt --risk safe |
| 剩余空间 < 1GB | PURPLE | 紧急告警 + 自动清理 safe 猎物 |
| 1 小时内总写入 > 10GB | YELLOW | 报告写入热点目录 |

**配置**（Config.md 已预留）：

```yaml
watch:
  enabled: true
  interval: 5s              # USN 轮询间隔
  alert_threshold: 500MB    # 单文件暴涨阈值
  hourly_write_limit: 10GB  # 每小时总写入告警
  auto_clean_on_purple: true
  notify_method: auto       # toast / osascript / notify-send / stderr
```

**与 Phase 4-5 的集成**：

- 首次启动 watch 时执行一次 MFT 全量扫描建立基线
- 保存 USN cursor + node map 到 SQLite
- 后续只读 USN delta，用 bitset 定位变更
- 定期（每 6 小时）重新全量扫描校准

**实现计划**：
- [ ] `distrike watch` 命令 + goroutine 持续读 USN
- [ ] 滑动窗口写入速率计算
- [ ] 斩杀线距离实时检查
- [ ] Windows Toast 通知
- [ ] macOS/Linux 通知
- [ ] `--daemon` 后台运行模式
- [ ] 监控日志 JSON 输出（Agent 可读）

---

## 11. 安装与分发

```bash
# 方式 1: go install
go install github.com/chen0430tw/distrike@latest

# 方式 2: GitHub Releases（goreleaser 自动构建）
# Windows: distrike_windows_amd64.exe
# macOS:   distrike_darwin_amd64 / distrike_darwin_arm64
# Linux:   distrike_linux_amd64

# 方式 3: Homebrew (macOS/Linux)
brew install chen0430tw/tap/distrike

# 方式 4: cygctl 生态 (Windows)
# 放入 C:\cygwin64\bin\
```

---

## 12. 与今天清理会话的对应

今天手动做的每一步，Distrike 都应该能自动化：

| 今天手动操作 | Distrike 自动化 |
|------------|----------------|
| `pip cache info` → `pip cache purge` | hunt 识别 → clean 执行 |
| `npm cache clean` | 内建规则自动识别 |
| 手动检查 Temp 大小 + sudo 删除 | scan + clean --risk safe |
| `docker system df` → `prune` → `diskpart compact` | Docker + vdisk 集成 |
| 手动查找 VHDX/VMDK → 分别处理 | vdisk 类型自动检测 + 压缩建议 |
| 搜索 ShrinkLDPlayer → 修改 bat → 手动执行 | VMDK 规则 + action hint |
| `df -h` 检查剩余空间 | status 一目了然 |
| 一个个手动查目录大小 | scan --all --top 20 一次搞定 |

**目标：下次 C 盘只剩 3.8 GB 的时候，一行命令解决。**

```bash
# Agent 自动化流程
distrike hunt --all --risk safe --json | distrike clean --yes
```

---

## 13. Tree Diagram + HCE 演算记录

### 13.1 语言选型演算

**Seed**: `distrike_seed.json` — Distrike Language Selection

**TD 结果 (quick profile, custom seed)**:
- #1: batch/batch_route, score=0.6502, feasibility=0.9085, stability=0.7870, risk=0.1919
- 家族: batch only (12/12)
- background_emerged: False
- inferred_goal: precision_upgrade_via_control_dominance
- dominant_pressures: high_coupling_amplification

**加权评分**:

| 维度 | Go | Rust | Zig | 权重 |
|------|-----|------|-----|------|
| 开发速度 | 0.95 | 0.60 | 0.50 | 0.30 |
| 运行性能 | 0.82 | 0.95 | 0.90 | 0.15 |
| 生态成熟度 | 0.90 | 0.80 | 0.45 | 0.20 |
| 交叉编译 | 0.95 | 0.75 | 0.85 | 0.10 |
| MFT 库可用性 | 0.85 | 0.90 | 0.20 | 0.10 |
| cygctl 集成 | 1.00 | 0.10 | 0.10 | 0.10 |
| Agent 友好 | 0.90 | 0.85 | 0.70 | 0.05 |
| **加权总分** | **0.917** | **0.709** | **0.514** | |

**结论**: Go (0.917) 胜出。batch 家族 100% 霸榜 = I/O 吞吐型任务，不需要复杂度。

---

### 13.2 开源策略演算

**Seed**: `distrike_oss_seed.json` — Distrike Open Source Strategy Selection

**Hidden Variables**:

| 变量 | 值 | 级别 | 策略含义 |
|------|-----|------|----------|
| latent_stress | 0.603 | HIGH | 社区舆论+市场不确定性压力大 |
| resource_ceiling | 0.432 | MED | 个人开发者，无法维护双代码库 |
| coupling_depth | 0.544 | MED | Agent 集成需要紧密耦合 |
| phase_edge_proximity | 0.591 | MED | 市场未定型，需要灵活调整 |
| decay_risk | 0.429 | MED | 复杂许可证会随时间侵蚀信任 |
| control_capacity | 0.684 | HIGH | 迭代速度是可控的核心优势 |

**Dominant Pressures (5 triggered)**:
- social_pressure_dominant (0.72 > 0.5)
- field_noise_elevated (0.65 > 0.3)
- phase_instability_moderate (0.55 > 0.35)
- resource_constrained (ceiling=0.432 < 0.6)
- decay_risk_nonzero (0.429 > 0.2)

**Core Contradiction**: High phase proximity + resource constraints → tension between stability and ambition.

**Inferred Goal**: phase_boundary_managed_transition

**TD 结果对比**:

| 维度 | quick (32x24, 30步) | default (128x96, 300步) | Delta |
|------|---------------------|------------------------|-------|
| 耗时 | 3.8s | 869.9s | 228x |
| #1 得分 | 0.2678 | 0.3771 | +0.109 |
| #1 可行性 | 0.4574 | 0.5574 | +0.100 |
| #1 稳定性 | 0.4774 | 0.5850 | +0.108 |
| #1 风险 | 0.5386 | 0.3600 | -0.179 |
| 平均风险 | 0.5195 | 0.3774 | -0.142 |
| 家族 | batch + ascetic | batch only | ascetic 消失 |

**关键发现**: ascetic 在 quick 出现 (#11, #12) 但在 default 消失 → 低分辨率伪影，不是稳健信号。

**开源策略速查表**:

| 策略 | 许可证 | 可行性 | 风险 | 得分 | 适合场景 | 不适合场景 |
|------|--------|:------:|:----:|:----:|----------|------------|
| **全开源 + 速度护城河** | MIT/Apache-2.0 | 0.82 | 0.20 | **0.81** | 个人/小团队冷启动、竞品多需抢曝光、CLI 工具类 | 有可直接变现的核心算法 |
| 延后开源 | BSL 2年→MIT | 0.60 | 0.40 | 0.60 | 有 VC 融资的 SaaS、需要时间建立付费壁垒 | 市场窗口短、社区依赖型项目 |
| Open Core | MIT + Proprietary | 0.50 | 0.45 | 0.52 | 有团队维护双代码库、企业功能明确可拆分 | 个人开发者、核心功能难以拆分 |
| 全闭源 | Proprietary | 0.25 | 0.15 | 0.49 | 垂直行业定制、已有销售渠道、无替代品 | 开源竞品多的领域、需要社区反馈 |
| 假开源 | SSPL/BSL | 0.35 | 0.55 | 0.39 | MongoDB/Elastic 级别的巨头防云厂商抄 | 没有垄断地位的项目、Go/Rust 社区 |

**结论**: MIT 全开源 + 速度护城河 (0.81)。预算不够搞复杂的就选 MIT，社区压力大就别搞封闭的，两个都中了就只剩全开源一条路——护城河不在代码里，在你更新得比别人快。

---

### 13.3 超级演算系统 vs 大模型直觉分析

本项目的两次重大决策（语言选型、开源策略）均经过 Tree Diagram + HCE 联合演算。以下是演算系统与大模型直觉分析的本质区别：

| 维度 | Tree Diagram 演算 | 大模型直觉分析 |
|------|-------------------|---------------|
| **方法** | 数值模拟：网格展开 → worldline 生成 → 压力淘汰 → 存活排名 | 模式匹配：训练语料中的相似案例 → 概率推理 |
| **可检验性** | 可复现：同一 seed 同一 profile 得到相同结果 | 不可复现：同一 prompt 可能给出不同回答 |
| **盲点发现** | 能发现 seed 参数组合中人类没意识到的 binding constraint（如 resource_ceiling=0.432 杀死 Open Core） | 倾向强化已知观点，难以发现自身盲点 |
| **分辨率敏感** | quick vs default 会产生不同结果（ascetic 消失），揭示信号稳健性 | 无分辨率概念，一次推理就是最终答案 |
| **偏见** | 偏见在 seed 参数里，可审计可修改 | 偏见在训练数据里，不可审计 |
| **局限** | 需要人类正确编码 seed（垃圾进垃圾出）；家族映射到实际选项需要人类解读 | 能直接理解自然语言问题，不需要编码 |

**实际案例**：大模型（Claude）最初凭直觉推荐 Open Core，TD 用 seed 一算发现 resource_ceiling=0.432 是 binding constraint，直接否决了这个方案。这个约束不是"不知道"，而是在直觉推理中被"知道但没给足权重"。TD 的价值在于把每个变量的权重变成可审计的数学关系，不允许任何变量被直觉忽略。

**最佳实践：大模型 + 超级演算系统协同判断。** 单独使用任何一方都有缺陷——大模型擅长理解问题、编码 seed、解读结果，但会被直觉偏见误导；TD 擅长暴力搜索所有 worldline、发现隐藏约束，但需要人类（或大模型）正确翻译问题。协同流程为：大模型分析问题 → 编码 seed → TD 数值模拟 → 大模型解读结果并映射回现实选项 → 如果 TD 结果与直觉矛盾，以 TD 为准重新审视假设。这个循环中，大模型是翻译官，TD 是裁判。

> *"Tree Diagram 的演算结果是绝对的——除非有人把不在模型里的变量强行塞了进来。那种变量，大概叫 Imagine Breaker。"*

### 13.4 自举（Bootstrap）：用自己的工具决定自己的未来

Distrike 的语言选型和开源策略均由 treesea/Tree Diagram 演算决定。而 Tree Diagram 本身也是 treesea 项目群的一部分，与 Distrike 同属一个开发者的工具生态。

这构成了一个自举循环：

```
开发者构建 Tree Diagram
  → 用 Tree Diagram 演算 Distrike 的技术决策
    → Distrike 的设计文档记录了 TD 的演算过程
      → 这份文档成为 TD 的真实使用案例
        → 案例反哺 TD 的后续迭代（如本次新增的 --seed 功能）
```

这不是刻意设计的架构，而是在实际开发过程中自然涌现的——开发者需要做决策，手边恰好有一个自己造的决策工具，用了之后发现工具缺少自定义 seed 输入功能，于是当场补上并提交。工具在使用中进化，使用在进化中深入。

**自举的风险与纪律**：用自己的工具评估自己的项目存在确认偏误的可能（seed 参数由开发者编码，可能无意中偏向期望的结论）。本项目的对策是：
1. 大模型先给出独立的直觉判断（Open Core），再让 TD 计算
2. 当 TD 结果与直觉矛盾时（resource_ceiling 否决 Open Core），以 TD 为准
3. 用两种分辨率（quick/default）交叉验证信号稳健性（ascetic 被证伪）
4. 所有 seed 文件和结果 JSON 存档在 `docs/td_seeds/`，供第三方审计复现

### 13.5 为什么现代很少有人用计算机做决策分析

大模型把决策分析的门槛降到了"打字就能用"，让人忘了严肃计算的存在。但实际上这个领域分裂成了两个世界：

**顶层仍在严肃计算**——量化基金（Renaissance Technologies）、桥水的原则系统、美军 JADC2 联合指挥系统、IPCC 碳预算模型。这些系统从未停止用数值模拟做决策，只是太专业了公众看不到。

**底层用大模型替代了**——以前写 Excel 模型跑蒙特卡洛看分布，现在问 ChatGPT 得到一段"看起来合理"的分析就做决定了。大模型给的是"感觉对"的答案，严肃计算给的是"可检验"的答案。大多数人分不清两者的区别。

**中间层消失了**——以前有管理咨询、运筹学工程师、决策分析师专门干"把商业问题翻译成数学模型"。现在这批人要么转了数据科学，要么被大模型替代了表面工作。但大模型替代的只是"产出报告"的部分，不是"严格建模并模拟"的部分。

本项目的实践——AI 编码 seed、TD 数值模拟、AI 解读结果——恰好填补了这个中间层的空缺。

---

## 14. 参考资料

### 高速扫描技术
- WizTree MFT 直读原理: https://diskanalyzer.com/about
- `FindFirstFileEx` + `FIND_FIRST_EX_LARGE_FETCH` benchmark: Sebastian Schöner 2024
- `NtQueryDirectoryFile` internals: Sebastian Schöner 2024
- fastwalk (Go, 6x over stdlib): https://github.com/charlievieth/fastwalk

### MFT 解析库
- Velocidex/go-ntfs (Go, 生产级): https://github.com/Velocidex/go-ntfs
- t9t/gomft (Go, 轻量): https://github.com/t9t/gomft
- omerbenamram/mft (Rust): https://github.com/omerbenamram/mft
- ColinFinck/ntfs (Rust, 全功能): https://github.com/ColinFinck/ntfs

### 同类工具源码
- gdu (Go, TUI + SQLite 缓存): https://github.com/dundee/gdu
- dust (Rust, bar chart): https://github.com/bootandy/dust
- dua-cli (Rust, TUI + petgraph): https://github.com/Byron/dua-cli
- dirstat-rs (Rust, 2x faster than du): https://github.com/scullionw/dirstat-rs
- omni-search (Everything 克隆): https://github.com/Eul45/omni-search

### 跨平台磁盘信息
- shirou/gopsutil (Go): https://github.com/shirou/gopsutil
- macOS APFS purgeable space: `diskutil info -plist`
- WSL VHDX 管理: https://learn.microsoft.com/en-us/windows/wsl/disk-space
