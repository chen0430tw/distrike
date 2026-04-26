# Distrike

*[English README](README.md)*

**你的磁盘又满了。Distrike 让这次成为最后一次。**

```
$ distrike status

C:\    [██████████████████████████████████████░░]  98.4%  7.4 GB free / 453 GB   DANGER
D:\    [██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  24.3%  3.4 TB free / 4.5 TB   OK
G:\    [████████████████████████████████████████]  99.5%  638 MB free / 115 GB   CRITICAL [USB]
```

```
$ distrike status   # 在 HPC 集群上（国研院台湾杉三号 / TWCC）

/              [████████░░░░░░░░░░░░░░░░░░░]  28.9%   154.8 GB   217.7 GB   OK[xfs]
/boot          [██████░░░░░░░░░░░░░░░░░░░░░]  24.0%   770.2 MB   1014 MB    OK[xfs]
/gpfs-work     [██████████████████░░░░░░░░░]  66.9%   2.5 PB     7.5 PB     OK[gpfs]
/gpfs-home     [███████████████░░░░░░░░░░░░]  53.8%   820.2 TB   1.7 PB     OK[gpfs]
/home          [██░░░░░░░░░░░░░░░░░░░░░░░░░]   7.3%   12.4 PB    13.4 PB    OK[nfs]
/work          [███████████░░░░░░░░░░░░░░░░]  39.7%   8.1 PB     13.4 PB    OK[nfs]
```

一条命令，覆盖从 USB 棒到 PB 级 GPFS 集群的所有挂载点。四色信号灯一眼告诉你当下处境。

## 安装

**推荐 —— 直接下二进制（无需装 Go）**：

从 [Releases](https://github.com/chen0430tw/distrike/releases) 下载。单文件静态二进制，无依赖、无 daemon。

> **Windows SmartScreen 拦截？** PowerShell 跑 `Unblock-File distrike.exe`，或右键 属性 → 解除锁定。

**从源码编译（需要 Go 1.25+）**：

```bash
go install github.com/chen0430tw/distrike@latest
```

> 依赖 `modernc.org/sqlite` 要求 Go 最低 1.25。老版本 Go 用预编译二进制即可。

## 能做什么

```bash
distrike status                      # 所有磁盘一览
distrike topo C:                     # 追踪磁盘空间去哪了
distrike hunt                        # 找出可清理项
distrike clean --risk safe --yes     # 自动清理
distrike watch --install             # 常驻监控避免再炸
```

**Topo 追流向 · Hunt 找猎物 · Clean 出击 · Watch 防复发**

## 能看见什么

190+ 条规则覆盖常见缓存、临时文件、垃圾源：

| 类别 | 覆盖 |
|------|------|
| **包管理缓存** | pip / conda / npm / yarn / cargo / Go modules / Maven / Gradle / ccache |
| **AI/ML 缓存** | HuggingFace hub / PyTorch hub / TensorFlow / Singularity 镜像 |
| **浏览器** | Chrome / Edge / Firefox / Brave — 只清缓存，不碰 cookies 和历史 |
| **IDE** | VS Code / JetBrains / vim / emacs |
| **应用** | Discord / Zoom / WeChat / QQ / OBS / Notepad++ |
| **容器** | Docker / Podman / Singularity / Apptainer |
| **虚拟磁盘** | VHDX / VMDK / VDI — 识别并可压缩 |
| **系统** | Windows Update / Temp / crash dumps / WER / Windows.old |
| **游戏** | Steam shader cache / Epic Vault |
| **HPC** | CUDA kernel cache / NVIDIA / AMD shader cache |

每条规则都有风险分级：**SAFE** 自动清，**CAUTION** 询问后清，**DANGER** 手动清。

标记 `[cosmetic]` 的项目（缩略图缓存、字体缓存等）会出现在列表里但被标注 —— 清掉它们对磁盘几乎没影响。

## HPC / 训练集群支持

单文件静态二进制，无 root 权限就能跑。

```bash
# 上传一次，随处可用
scp distrike_linux user@cluster:/work/user/distrike

# 查看所有集群文件系统
./distrike status

# 找出悄悄吃 quota 的东西
./distrike hunt /home/user
./distrike hunt /work/user
```

**台湾杉三号首次运行**立刻找到 31.1 GB 可回收：

```
[SAFE]  26.2 GB  /home/user/.singularity/cache
  Kind: cache  Description: Singularity image layer cache
  Cleanup: singularity cache clean --force

[SAFE]   4.9 GB  /home/user/.cache/pip
  Kind: cache  Description: pip wheel/package download cache
  Cleanup: pip cache purge
```

### 模型权重清点

训练过程会堆积大量 checkpoint。打开扫描权重：

```bash
distrike config set hunt.scan_model_weights true
distrike hunt /work/user
```

识别：`.safetensors` `.gguf` `.ggml` `.pt` `.pth` `.ckpt` `.h5` `.hdf5` `.onnx` `.pb`

**CAUTION 评级** —— Distrike 只报告，绝不自动删除模型权重。

### 文件系统识别

| 文件系统 | 出现位置 | 说明 |
|---|---|---|
| `gpfs` | IBM Spectrum Scale 集群 | PB 级共享存储 |
| `wekafs` | Weka HPC 集群 | 高性能 NVMe-over-fabric |
| `nfs` | 绝大多数集群 | quota 管理很关键 |
| `xfs` | Linux 计算节点 | HPC 默认文件系统 |
| `vfat` | /boot/efi | 小系统分区 — 不会误报 CRITICAL |
| `tmpfs` | /dev/shm | 仅当用户创建时可见 |
| `ReFS` | Windows Server | fastwalk 引擎，无 MFT |

小系统分区（`/boot`、`/boot/efi`）**永远不会误触发 CRITICAL** —— 阈值按分区大小自适应。

## 为什么信号不按百分比算

1 TB 磁盘用到 97% 还有 30 GB 空间。120 GB 磁盘用到 99% 只剩 600 MB。同样的进度条，完全不同的危险程度。

Distrike 用**绝对剩余空间**对比**kill-line 阈值**：

| 信号 | 条件 | |
|--------|-----------|---|
| **PURPLE** | < 1 GB | 灾难迫在眉睫 |
| **RED** | < kill-line（默认 20 GB）| 立刻清理 |
| **YELLOW** | < kill-line × 1.5 | 需要注意 |
| **GREEN** | 高于阈值 | 安全 |

小分区（总容量 < kill-line）用比例阈值代替，所以 `/boot/efi` 只剩 194 MB（总 200 MB）会显示 **OK** 而不是 CRITICAL。

### 为什么 kill-line 默认是 20 GB

低于 20 GB 时 Windows 进入**死亡螺旋** —— 系统吃空间的速度超过你释放的速度：

| 机制 | 需求空间 | 饿死时的后果 |
|---|---|---|
| **pagefile.sys 扩张** | 3–5 GB | 内存不足 → Windows 扩虚拟内存 → 占更多空间 |
| **Windows Update** | ~8 GB | 补丁需要临时空间解包 → 失败回滚（更占空间）|
| **VHDX 膨胀** | 2–3 GB | WSL/Docker VHDX 没空间无法压缩 → 只增不减 |
| **NTFS 碎片** | — | 没有连续空闲块 → MFT 碎片化 → 性能崩溃 |
| **应用临时文件** | 2–3 GB | Chrome / VS Code / 游戏写临时文件 → 写入失败 → 崩溃 |

合计约 **18–20 GB 是系统正常运行的最低缓冲**。

所以叫它 **kill-line（斩杀线）**，不是警告线。越过就无法自救，需要人工干预。完整数学推导见 [DESIGN.md](docs/DESIGN.md)。

## Distrike vs Windows SilentCleanup

Windows 自带一个清理任务 `\Microsoft\Windows\DiskCleanup\SilentCleanup`，会在剩余空间低于 ~200 MB 或系统空闲 ≥1 小时时自动跑。它本质上就是 `cleanmgr.exe /autoclean`，从注册表 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches` 读"被认证的清理处理器"列表。

很有用，但能力有限。Distrike 是来填空的。

| | Windows SilentCleanup | Distrike |
|---|---|---|
| 触发方式 | 自动：低空间 + 1 小时空闲 | 手动 / 定时 / `watch --auto-clean` |
| 覆盖范围 | `VolumeCaches` 里 `Autorun=1` 的 handler | 内置 190+ 规则 + 注册表 handler + vdisk + 第三方应用 |
| 风险模型 | 无（二选一：清或不清） | 三档 Safe / Caution / Danger，每个应用语义化 |
| QQ / 微信 / Discord | 完全不碰 | 识别并区分"缓存" vs "不可恢复的用户数据" |
| WSL / Docker / Hyper-V VHDX | 完全不碰 | 识别 + 集成 `fstrim` + `diskpart compact` 工作流 |
| HuggingFace / pip / cargo / Singularity | 完全不碰 | 识别并给出回收命令 |
| 自定义规则 | 不支持 | 白名单 + 自定义规则文件 |
| 审计 | 只有 `LastTaskResult` | JSON 输出 / scan cache / watch 趋势日志 |

**Distrike 读的是跟 SilentCleanup 同一个 `VolumeCaches` 注册表**，所以 NVIDIA / Adobe / Visual Studio 等装过的第三方清理 handler 也会出现在 `hunt` 输出里，标 `[VolumeCaches]` 做来源透明。重叠时内置规则优先。重要注意点：

- 大多数 handler 注册的是 COM-only 目标（`IEmptyVolumeCache`），没有可解析的路径——这些会被跳过。
- 任何 `Folder` 字段指向驱动器根 / `%SystemRoot%` / `%UserProfile%` / 顶层用户库（`Downloads`、`Documents` 等）的 handler 也会被跳过：那个字段是 cleanmgr COM 逻辑的*扫描根*，不是"删整个目录"的指令。递归删掉会出大事。
- 出于同一原因，**所有 `[VolumeCaches]` 规则都标 DANGER**，提示使用 `cleanmgr` 而不是 `distrike clean`。Distrike 不会自动删这些路径。

**推荐工作流**：让 SilentCleanup 后台搞定 OS 已知安全项，剩下的（聊天软件、VHDX、容器镜像、HPC 缓存）交给 `distrike hunt`。

### 关于 QQ 自带的清理功能

QQ 自带清理入口在 **设置 → 存储管理 → 清理缓存**。它是清 QQ 的**最安全**选项——它知道哪些是渲染缓存、哪些是聊天正本——但它能力很有限：

- 只清渲染缓存和少数已知 temp 目录；**完全不动 `nt_qq/nt_data/Pic` 和 `Video`**（即那些动辄几十 GB 的本体存储）
- 没有 glob / 预览 / 白名单，点之前看不到要删什么
- 没有 CLI / 脚本接口

Distrike 会*识别* QQ 本地图片/视频存储并报告大小，但风险评级是 `DANGER`——腾讯服务器只在漫游期内（7天/30天/2年，按会员等级）保留原图，超过期限后本地这份**就是唯一一份**。建议先用 QQ 自带清理跑一遍安全清理，要动 `nt_data/Pic|Video` 务必先把重要图片另存为，再让 `distrike clean` 动手。

## 绝对不碰什么

- Cookies、浏览历史、保存的密码、书签
- Windows Run 历史、最近文件、跳转列表
- 你的文档、项目、源代码、模型权重（除非你明确打开 `scan_model_weights`）

## v0.3.0 新特性

**响应式表格 + Unix 哲学 TSV 管道模式**

- **响应式布局**：Bootstrap 风格断点（xs/sm/md/lg/xl/xxl），表格自动按终端宽度丢列。窄终端依次丢 Total → Used% → Usage bar。
- **TSV 管道输出**：管道重定向自动切换成 tab 分隔、原始字节、完整精度 —— 和 `awk` / `cut` / `jq` 无缝组合。
- **`--format` flag**：显式选 `auto` / `table` / `tsv` / `json`。老的 `--json` 向后兼容。
- **SSH 安全宽度**：TermWidth fallback 从 120 降到 80，`wsl ssh host "distrike status"` 不再把窄终端挤崩。

### 技术文档

`docs/cascadia-shade-deconstruction.md` —— 611 行 **Windows 文本渲染栈考古 post-mortem**。为了设计一个"左半实心 + 右半网底"的过渡字符挖了一整天，最后证明**物理不可能**（Windows Terminal 用 HLSL shader 屏幕绝对坐标自绘 `░`，完全绕过字体）。保留整个失败过程作为给后来者省 8–12 小时的地图。

## 架构

- Go 单文件二进制，三套扫描引擎：MFT 直读（Windows Admin）/ fastwalk（跨平台）/ USN Journal（增量）
- 莫比乌斯环式控制流：`status → topo → hunt → clean → watch → status`
- SQLite 持久化 scan cache（支持挂载变化自动失效）
- 跨平台：Windows / Linux / macOS（Intel + ARM）

详见 [DESIGN.md](docs/DESIGN.md) 和 [DESIGN_PHILOSOPHY.md](docs/DESIGN_PHILOSOPHY.md)。

## 许可证

MIT. 见 [LICENSE](LICENSE)。

---

> **"Your disk is full again. Distrike makes sure it's the last time."**
>
> 开发者：[@chen0430tw](https://github.com/chen0430tw) · 2026
