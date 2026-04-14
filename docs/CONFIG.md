# Distrike 配置文档

## 配置文件位置

| 平台 | 路径 |
|------|------|
| Windows | `%APPDATA%\distrike\config.yaml` |
| macOS | `~/Library/Application Support/distrike/config.yaml` |
| Linux | `~/.config/distrike/config.yaml` |

首次运行 `distrike` 时自动生成默认配置。

---

## 完整配置参考

```yaml
# ============================================================
# Distrike Configuration
# ============================================================
# 修改后立即生效，无需重启。
# Agent 可通过 distrike config set <key> <value> 修改。
# 也可直接编辑此文件。
# ============================================================

# ------------------------------------------------------------
# 1. 斩杀线 (Kill Line)
# ------------------------------------------------------------
# 剩余空间低于此值时进入 CRITICAL 状态。
# 支持单位: B, KB, MB, GB, TB
# 默认: 20GB
kill_line: 20GB

# 斩杀线倍数：
#   SAFE     = 剩余 > kill_line * safe_multiplier
#   WARNING  = kill_line < 剩余 < kill_line * safe_multiplier
#   CRITICAL = 剩余 < kill_line
# 默认: 2.0（即 40GB 以上为 SAFE）
safe_multiplier: 2.0

# 按盘/挂载点覆盖斩杀线（可选）
# 未列出的盘使用全局 kill_line
kill_line_overrides:
  # C 盘空间更紧张，斩杀线设低一点
  # "C:\\": 10GB
  # macOS 用户目录
  # "/Users": 30GB

# ------------------------------------------------------------
# 2. 容量灯号系统 (Capacity Signal)
# ------------------------------------------------------------
# 四色灯号，借鉴 CFPAI 风险信号体系。
# 基于三个维度判定：已用比例 + 集中度(HHI) + 剩余预算
signal:
  # 是否启用灯号系统（替代简单的三级斩杀线）
  enabled: true

  # 灯号阈值（优先级由高到低判定）
  thresholds:
    # PURPLE（极度危险）: used > 90% AND concentration > 60% AND free < kill_line
    purple:
      used_ratio: 0.90
      concentration: 0.60
      requires_below_kill_line: true

    # RED（危险）: used > 85% AND concentration > 50%
    red:
      used_ratio: 0.85
      concentration: 0.50

    # YELLOW（注意）: used > 70% OR concentration > 35%
    yellow:
      used_ratio: 0.70
      concentration: 0.35
      # yellow 使用 OR 逻辑（任一条件满足即触发）
      logic: or

    # GREEN（正常）: 以上均不满足时

  # 综合风险评分权重
  # risk_pct = min(100, used_ratio * used_weight + concentration * concentration_weight)
  risk_weights:
    used_ratio: 60       # 已用比例权重
    concentration: 40    # 集中度权重

  # 集中度计算的 Top-N（取前 N 个目录计算 HHI）
  concentration_top_n: 10

# ------------------------------------------------------------
# 3. 存储健康检测
# ------------------------------------------------------------
health:
  # 是否启用存储健康检测
  enabled: true

  # SMART 健康检查
  smart:
    enabled: true
    # smartctl 路径（auto = 自动检测，未安装则跳过）
    smartctl_path: auto

  # 容量异常检测（山寨 U 盘/SD 卡识别）
  capacity_anomaly:
    # 是否启用
    enabled: true
    # 只检测可移动设备（U盘/SD卡）
    removable_only: true
    # 标称 vs 实际差距超过此比例时报警
    # 0.10 = 差距超过 10% 触发 YELLOW
    threshold: 0.10

  # 坏道检测（通过 SMART Reallocated_Sector_Ct）
  bad_sectors:
    enabled: true
    # 重新分配扇区数超过此值时报警
    warning_threshold: 5     # YELLOW
    critical_threshold: 50   # RED

  # SSD/闪存寿命检测
  wear_level:
    enabled: true
    # 剩余寿命低于此百分比时报警
    warning_pct: 20          # YELLOW: 寿命 < 20%
    critical_pct: 5          # RED: 寿命 < 5%

  # 文件系统错误检测
  fs_errors:
    enabled: true

# ------------------------------------------------------------
# 4. 加密与权限
# ------------------------------------------------------------
security:
  # 加密磁盘处理
  encryption:
    # 检测加密状态（BitLocker / FileVault / LUKS）
    detect: true
    # 锁定的加密磁盘是否纳入灯号计算
    include_locked_in_signal: false

  # 权限不足处理策略
  # skip  = 跳过并记录（默认）
  # warn  = 跳过并在输出中警告
  access_denied_policy: skip

  # 扫描覆盖率低于此值时输出警告
  # 建议 Agent 以管理员权限重新扫描
  min_coverage_warning: 0.80

scan:
  # 默认扫描深度（目录层级）
  # 0 = 无限制
  max_depth: 3

  # 最小显示大小，低于此值的条目不显示
  # 支持单位: B, KB, MB, GB
  min_size: 100MB

  # 默认显示的 Top-N 条目数
  top: 20

  # 是否跟踪符号链接/junction
  follow_symlinks: false

  # 扫描引擎选择
  # auto     = 自动选择最快引擎
  # fastwalk = 并发目录遍历（默认 fallback）
  # mft      = NTFS MFT 直读（Windows Admin only，最快）
  engine: auto

  # HDD/SSD 检测模式
  # auto   = 自动检测存储介质类型，SSD 并发/HDD 串行
  # ssd    = 强制并发模式
  # hdd    = 强制串行模式
  storage_mode: auto

  # 并发 worker 数量
  # 0 = 自动（GOMAXPROCS * 2）
  workers: 0

  # 排除目录（扫描时完全跳过）
  exclude:
    - "$RECYCLE.BIN"
    - "System Volume Information"
    - ".git"
    - "node_modules"
    # Linux/macOS 伪文件系统
    - "/proc"
    - "/sys"
    - "/dev"
    - "/run"

# ------------------------------------------------------------
# 3. 扫描缓存
# ------------------------------------------------------------
cache:
  # 是否启用 SQLite 扫描缓存
  # 开启后重复查看同一路径可秒开
  enabled: true

  # 缓存过期时间
  # 支持: 30m, 1h, 6h, 24h, 7d
  ttl: 1h

  # 缓存文件位置（auto = 配置目录下）
  path: auto

  # 缓存最大大小
  max_size: 100MB

# ------------------------------------------------------------
# 4. 猎物识别 (Hunt)
# ------------------------------------------------------------
hunt:
  # 是否启用内建规则
  builtin_rules: true

  # 内建规则类别开关
  # 设为 false 可禁用整个类别
  categories:
    cache: true       # 缓存类（pip, npm, cargo 等）
    temp: true        # 临时文件类
    vdisk: true       # 虚拟磁盘类（VHDX, VMDK 等）
    backup: true      # 备份类（iPhone, Windows 镜像等）
    download: true    # 下载类
    orphan: true      # 孤儿/残留类
    log: true         # 日志类

  # 默认风险过滤（hunt 输出时）
  # all / safe / caution / danger
  default_risk_filter: all

  # 最小猎物大小（低于此值不报告）
  min_prey_size: 50MB

# ------------------------------------------------------------
# 5. 白名单
# ------------------------------------------------------------
# 白名单中的路径永远不会被标记为猎物。
# 支持绝对路径和 glob 模式。
# Agent 可通过 distrike config whitelist add/remove 修改。
whitelist:
  # Windows 示例
  # - "D:\\GenshinImpact_4.0.1"
  # - "D:\\Star Rail"
  # - "D:\\APT-Transformer"
  # macOS 示例
  # - "~/Projects"
  # Linux 示例
  # - "/opt/important-data"
  # glob 模式
  # - "*/node_modules"  # 不报告 node_modules 为猎物

# ------------------------------------------------------------
# 6. 自定义猎物规则
# ------------------------------------------------------------
# 在内建规则之外添加自定义检测规则。
# Agent 可通过 distrike config rule add 修改。
custom_rules: []
  # 示例:
  # - pattern: "*/LDPlayer/*/vms/*/data.vmdk"
  #   kind: vdisk
  #   risk: caution
  #   platform: windows          # windows / darwin / linux / all
  #   description: "雷电模拟器虚拟磁盘"
  #   action:
  #     type: manual             # command / manual
  #     hint: "使用 ShrinkLDPlayer 工具压缩"
  #
  # - pattern: "*/BaiduNetdiskDownload"
  #   kind: download
  #   risk: caution
  #   platform: all
  #   description: "百度网盘下载缓存"
  #   action:
  #     type: manual
  #     hint: "确认文件已使用后手动删除"

# ------------------------------------------------------------
# 7. 清理设置
# ------------------------------------------------------------
clean:
  # 清理前是否需要确认
  # true  = 交互确认（默认，人类使用）
  # false = 静默执行（Agent 使用时配合 --yes）
  confirm: true

  # 清理后是否自动重新扫描验证
  verify_after_clean: true

  # 是否保留清理历史
  history: true
  max_history: 100

# ------------------------------------------------------------
# 8. Docker 集成
# ------------------------------------------------------------
docker:
  # 是否启用 Docker 检测
  enabled: true

  # Docker 可执行文件路径（auto = 自动检测）
  executable: auto

  # 自动检测的内容
  detect:
    dangling_images: true      # 悬空镜像
    stopped_containers: true   # 已停止容器
    unused_volumes: true       # 未使用卷
    build_cache: true          # 构建缓存

  # 停止容器超过此时间才标记为猎物
  stopped_threshold: 7d

# ------------------------------------------------------------
# 9. WSL 集成 (Windows only)
# ------------------------------------------------------------
wsl:
  # 是否启用 WSL 检测
  enabled: true

  # 自动检测所有 WSL 发行版的 VHDX 大小
  detect_vhdx: true

  # 建议启用 sparse 模式的阈值
  # VHDX 大小超过此值且未启用 sparse 时发出建议
  sparse_suggest_threshold: 10GB

  # compact 前是否自动 fstrim
  auto_fstrim: true

# ------------------------------------------------------------
# 10. 虚拟磁盘集成
# ------------------------------------------------------------
vdisk:
  # 是否扫描虚拟磁盘文件
  enabled: true

  # 虚拟磁盘最小报告大小
  min_size: 1GB

  # 压缩工具路径（auto = 自动检测）
  tools:
    # diskpart 路径（Windows 内建）
    diskpart: auto
    # vmware-vdiskmanager 路径
    vdiskmanager: auto
    # VBoxManage 路径
    vboxmanage: auto

# ------------------------------------------------------------
# 11. 输出设置
# ------------------------------------------------------------
output:
  # 默认输出格式
  # text / json
  format: text

  # 是否显示进度条（text 模式）
  progress: true

  # 颜色输出
  # auto / always / never
  color: auto

  # JSON 输出是否美化
  json_indent: true

  # 日期时间格式
  # iso8601 / unix / human
  time_format: iso8601

# ------------------------------------------------------------
# 12. 通知设置（Phase 6）
# ------------------------------------------------------------
# notify:
#   # 斩杀线告警通知
#   enabled: false
#   # 通知方式: toast (Windows) / osascript (macOS) / notify-send (Linux)
#   method: auto
#   # 定时检查间隔
#   interval: 6h
```

---

## Agent 操作速查

### 查看配置

```bash
# 查看完整配置
distrike config show

# 查看指定项
distrike config get kill_line
distrike config get scan.engine
distrike config get docker.enabled

# JSON 输出（Agent 解析用）
distrike config show --json
```

### 修改配置

```bash
# 设置斩杀线
distrike config set kill_line 20GB
distrike config set kill_line 10GB     # C 盘空间紧张时调低

# 设置扫描参数
distrike config set scan.max_depth 5
distrike config set scan.min_size 50MB
distrike config set scan.top 30
distrike config set scan.engine mft    # 强制 MFT 模式（需 Admin）
distrike config set scan.engine auto   # 恢复自动选择

# 设置缓存
distrike config set cache.enabled true
distrike config set cache.ttl 6h

# 设置 Docker
distrike config set docker.enabled true
distrike config set docker.stopped_threshold 30d

# 设置 WSL
distrike config set wsl.enabled true
distrike config set wsl.sparse_suggest_threshold 20GB
```

### 灯号与健康配置

```bash
# 调整灯号阈值
distrike config set signal.thresholds.yellow.used_ratio 0.75   # 更早触发黄灯
distrike config set signal.thresholds.red.used_ratio 0.80      # 更早触发红灯

# 调整风险权重
distrike config set signal.risk_weights.used_ratio 70          # 更重视已用比例
distrike config set signal.risk_weights.concentration 30       # 降低集中度权重

# 禁用灯号（回退到简单斩杀线模式）
distrike config set signal.enabled false

# 存储健康检测
distrike config set health.enabled true
distrike config set health.smart.enabled true
distrike config set health.capacity_anomaly.removable_only true  # 只检测U盘
distrike config set health.wear_level.warning_pct 30             # SSD 寿命 30% 报警

# 加密与权限
distrike config set security.access_denied_policy warn           # 权限不足时警告
distrike config set security.min_coverage_warning 0.90           # 覆盖率 90% 以下警告
```

### 白名单管理

```bash
# 添加白名单
distrike config whitelist add "D:\GenshinImpact_4.0.1"
distrike config whitelist add "D:\Star Rail"
distrike config whitelist add "D:\APT-Transformer"
distrike config whitelist add "~/Projects"

# 删除白名单
distrike config whitelist remove "D:\Star Rail"

# 查看白名单
distrike config whitelist list
distrike config whitelist list --json
```

### 自定义规则管理

```bash
# 添加规则
distrike config rule add \
  --pattern "*/LDPlayer/*/vms/*/data.vmdk" \
  --kind vdisk \
  --risk caution \
  --platform windows \
  --description "雷电模拟器虚拟磁盘" \
  --action-type manual \
  --action-hint "使用 ShrinkLDPlayer 工具压缩"

# 添加缓存清理规则
distrike config rule add \
  --pattern "*/AppData/Local/JetBrains/*/caches" \
  --kind cache \
  --risk safe \
  --platform windows \
  --description "JetBrains IDE 缓存" \
  --action-type command \
  --action-command "rm -rf"

# 列出自定义规则
distrike config rule list

# 删除规则（按索引）
distrike config rule remove 0
```

### 按盘覆盖斩杀线

```bash
# C 盘用 10GB 斩杀线（空间紧张）
distrike config set kill_line_overrides.C:\\ 10GB

# D 盘用 30GB 斩杀线（项目多）
distrike config set kill_line_overrides.D:\\ 30GB

# macOS
distrike config set kill_line_overrides./ 15GB
```

### 猎物类别开关

```bash
# 禁用下载类检测（不想被提醒 Downloads 文件夹太大）
distrike config set hunt.categories.download false

# 禁用备份类检测（iPhone 备份不想动）
distrike config set hunt.categories.backup false

# 重新启用
distrike config set hunt.categories.backup true
```

---

## Agent 自动化完整示例

```bash
# === 场景：Agent 发现 C 盘空间不足 ===

# 1. 检查斩杀线状态
distrike status --json
# 返回: {"drives": [{"path": "C:\\", "status": "CRITICAL", "free_bytes": ...}]}

# 2. 猎杀 C 盘，只看安全猎物
distrike hunt C:\ --risk safe --json
# 返回: {"prey": [{"path": "...", "action": {"command": "pip cache purge"}}]}

# 3. 自动清理所有安全猎物
distrike clean --risk safe --yes --json
# 返回: {"cleaned": [...], "freed_bytes": 3800000000}

# 4. 验证状态
distrike status --json
# 返回: {"drives": [{"path": "C:\\", "status": "WARNING", ...}]}

# 5. 如果还不够，查看 caution 级猎物让用户决定
distrike hunt C:\ --risk caution --json
```

```bash
# === 场景：定期维护 ===

# 全盘快速检查
distrike status

# 如果有 WARNING/CRITICAL，全盘猎杀
distrike hunt --all

# 安全清理
distrike clean --risk safe --yes

# WSL 压缩（如果有）
distrike wsl compact --all
```

---

## 配置文件格式说明

### 大小单位

| 单位 | 含义 | 示例 |
|------|------|------|
| B | 字节 | 1024B |
| KB | 千字节 | 500KB |
| MB | 兆字节 | 100MB |
| GB | 吉字节 | 20GB |
| TB | 太字节 | 1TB |

### 时间单位

| 单位 | 含义 | 示例 |
|------|------|------|
| m | 分钟 | 30m |
| h | 小时 | 1h, 6h |
| d | 天 | 7d, 30d |

### 平台标识

| 值 | 含义 |
|------|------|
| windows | Windows (含 Cygwin) |
| darwin | macOS |
| linux | Linux (含 WSL) |
| all | 所有平台 |

### 风险等级

| 值 | 含义 | 自动清理 |
|------|------|----------|
| safe | 安全，可自动清理 | 允许 `--yes` |
| caution | 需要确认，可能有用 | 需要交互确认 |
| danger | 高风险，可能不可恢复 | 必须手动操作 |

### 猎物类型

| 值 | 含义 | 示例 |
|------|------|------|
| cache | 缓存文件 | pip, npm, cargo, gradle |
| temp | 临时文件 | Windows Temp, crash dumps |
| vdisk | 虚拟磁盘 | VHDX, VMDK, VDI |
| backup | 备份文件 | iPhone 备份, 系统镜像 |
| download | 下载文件 | Downloads, BaiduNetdisk |
| orphan | 孤儿/残留 | 已卸载软件残留 |
| log | 日志文件 | 系统日志, 应用日志 |
