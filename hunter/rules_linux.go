// go:build linux

package hunter

func platformSpecificRules() []Rule {
	return []Rule{
		// ── Package managers ──────────────────────────────────────────────────

		// APT
		{Pattern: "/var/cache/apt", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "APT package cache",
			Action:      Action{Type: "command", Command: "sudo apt clean", Shell: "bash"}},

		// DNF / YUM (Fedora, RHEL, CentOS)
		{Pattern: "/var/cache/dnf", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "DNF/YUM package cache",
			Action:      Action{Type: "command", Command: "sudo dnf clean all", Shell: "bash"}},
		{Pattern: "/var/cache/yum", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "YUM package cache",
			Action:      Action{Type: "command", Command: "sudo yum clean all", Shell: "bash"}},

		// Pacman (Arch Linux)
		{Pattern: "/var/cache/pacman/pkg", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Pacman downloaded package cache",
			Action:      Action{Type: "command", Command: "sudo pacman -Scc --noconfirm", Shell: "bash"}},

		// Snap
		{Pattern: "/var/lib/snapd", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Snap package data",
			Action:      Action{Type: "manual", Hint: "sudo snap remove --purge <unused-snap>"}},

		// Orphan packages
		{Pattern: "__runtime_detect__orphan_packages", Kind: KindOrphan, Risk: RiskSafe, Platform: "linux",
			Description: "Orphaned packages",
			Action:      Action{Type: "command", Command: "sudo apt autoremove -y", Shell: "bash"}},

		// ── Developer caches — Python ─────────────────────────────────────────

		// Python bytecode
		{Pattern: "*/__pycache__", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Python bytecode cache (auto-regenerates on import)",
			Action:      Action{Type: "manual", Hint: "find . -type d -name __pycache__ -exec rm -rf {} +"}},
		{Pattern: "**/*.pyc", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Compiled Python bytecode files",
			Action:      Action{Type: "manual", Hint: "find . -name '*.pyc' -delete"}},

		// pip cache
		{Pattern: "*/.cache/pip", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "pip wheel/package download cache",
			Action:      Action{Type: "command", Command: "pip cache purge", Shell: "bash"}},
		{Pattern: "*/.cache/pipenv", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "pipenv package cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/pipenv"}},

		// conda / mamba
		{Pattern: "*/.conda/pkgs", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Conda downloaded package tarballs (~500MB–5GB)",
			Action:      Action{Type: "command", Command: "conda clean --all -y", Shell: "bash"}},
		{Pattern: "*/anaconda3/pkgs", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Anaconda3 package cache",
			Action:      Action{Type: "command", Command: "conda clean --all -y", Shell: "bash"}},
		{Pattern: "*/miniconda3/pkgs", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Miniconda3 package cache",
			Action:      Action{Type: "command", Command: "conda clean --all -y", Shell: "bash"}},

		// Jupyter
		{Pattern: "*/.ipynb_checkpoints", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Jupyter notebook auto-checkpoint files",
			Action:      Action{Type: "manual", Hint: "find ~ -type d -name .ipynb_checkpoints -exec rm -rf {} +"}},

		// ── Developer caches — AI / ML ────────────────────────────────────────

		// Hugging Face (can be 100+ GB on HPC nodes)
		{Pattern: "*/.cache/huggingface/hub", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Hugging Face model hub cache (can be 100+ GB)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/huggingface/hub"}},
		{Pattern: "*/.cache/huggingface/datasets", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Hugging Face datasets cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/huggingface/datasets"}},

		// PyTorch hub
		{Pattern: "*/.cache/torch/hub", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "PyTorch hub model cache (~500MB–50GB)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/torch/hub"}},
		{Pattern: "*/.torch", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "PyTorch legacy model cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.torch"}},

		// CUDA shader / driver cache
		{Pattern: "*/.nv", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "NVIDIA CUDA compiled kernel/shader cache (regenerates automatically)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.nv"}},
		{Pattern: "*/.cache/cuda", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "CUDA runtime cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/cuda"}},

		// ── Developer caches — JS / Node ─────────────────────────────────────

		// npm
		{Pattern: "*/.cache/npm", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "npm package download cache",
			Action:      Action{Type: "command", Command: "npm cache clean --force", Shell: "bash"}},
		{Pattern: "*/.npm", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "npm legacy cache directory",
			Action:      Action{Type: "command", Command: "npm cache clean --force", Shell: "bash"}},

		// Yarn
		{Pattern: "*/.cache/yarn", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Yarn package cache (~300MB–1.5GB)",
			Action:      Action{Type: "command", Command: "yarn cache clean", Shell: "bash"}},

		// ── Developer caches — Compiled languages ────────────────────────────

		// Rust / Cargo
		{Pattern: "*/.cargo/registry", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Cargo crate registry cache (~200MB–2GB)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cargo/registry"}},
		{Pattern: "*/.cargo/git", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Cargo git-source cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cargo/git"}},

		// Go modules
		{Pattern: "*/go/pkg/mod", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Go module download cache (~500MB–5GB)",
			Action:      Action{Type: "command", Command: "go clean -modcache", Shell: "bash"}},

		// C/C++ compiler cache
		{Pattern: "*/.ccache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "ccache compiler output cache (safe to purge, rebuilds on next compile)",
			Action:      Action{Type: "command", Command: "ccache --clear", Shell: "bash"}},

		// CMake build artifacts
		{Pattern: "**/CMakeFiles", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "CMake generated build files",
			Action:      Action{Type: "manual", Hint: "find . -type d -name CMakeFiles -exec rm -rf {} +"}},

		// ── Developer caches — JVM ────────────────────────────────────────────

		// Maven
		{Pattern: "*/.m2/repository", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Maven local dependency repository (~1GB–10GB)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.m2/repository"}},

		// Gradle
		{Pattern: "*/.gradle/caches", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Gradle build cache (~2GB–35GB); check for API keys in gradle.properties first",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.gradle/caches ~/.gradle/.tmp"}},

		// Coursier (Scala / SBT)
		{Pattern: "*/.cache/coursier", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Coursier/SBT artifact cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/coursier"}},

		// ── IDEs & editors ────────────────────────────────────────────────────

		// JetBrains (IntelliJ, PyCharm, CLion, etc.)
		{Pattern: "*/.cache/JetBrains", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "JetBrains IDE cache (old versions accumulate after updates, ~1GB–30GB)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/JetBrains"}},

		// Vim
		{Pattern: "*/.vim/.swp", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Vim swap files",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.vim/.swp/*"}},
		{Pattern: "*/.vim/.backup", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Vim backup files",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.vim/.backup/*"}},
		{Pattern: "*/.vim/.undo", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Vim persistent undo history",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.vim/.undo/*"}},

		// Emacs
		{Pattern: "*/.emacs.d/auto-save-list", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Emacs auto-save session records",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.emacs.d/auto-save-list/*"}},
		{Pattern: "*/.emacs.d/backups", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Emacs file backups (tilde files)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.emacs.d/backups/*"}},

		// ── Browser caches ────────────────────────────────────────────────────

		{Pattern: "*/.cache/google-chrome/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Google Chrome cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.cache/chromium/Default/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Chromium cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.config/BraveSoftware/Brave-Browser/*/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Brave browser cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.mozilla/firefox/*/cache2", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Firefox disk cache",
			Action:      Action{Type: "manual", Hint: "Delete cache2 contents"}},
		{Pattern: "*/.cache/firefox", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Firefox cache (snap/flatpak layout)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/firefox"}},

		// ── App caches ────────────────────────────────────────────────────────

		// Electron apps
		{Pattern: "*/.config/discord/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Discord cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.config/Code/Cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "VS Code cache",
			Action:      Action{Type: "manual", Hint: "Delete cache contents"}},
		{Pattern: "*/.config/Code/CachedData", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "VS Code cached data",
			Action:      Action{Type: "manual", Hint: "Delete cached data"}},

		// Fontconfig
		{Pattern: "*/.cache/fontconfig", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Font index cache (regenerates on next GUI app launch)",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/fontconfig/*"}},

		// R statistics
		{Pattern: "*/.cache/R", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "R package/data cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/R/*"}},

		// Wine
		{Pattern: "*/.wine/drive_c/users/*/AppData/Local/Temp", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "Wine Windows temp folder",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.wine/drive_c/users/*/AppData/Local/Temp/*"}},

		// ── Containers ────────────────────────────────────────────────────────

		// Docker
		{Pattern: "/var/lib/docker/overlay2", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Docker image layers (run 'docker system df' first)",
			Action:      Action{Type: "command", Command: "docker system prune -af", Shell: "bash"}},

		// Podman (rootless)
		{Pattern: "*/.local/share/containers/storage", Kind: KindCache, Risk: RiskCaution, Platform: "linux",
			Description: "Podman rootless container/image storage (~500MB–50GB)",
			Action:      Action{Type: "command", Command: "podman system prune --all -f", Shell: "bash"}},

		// Singularity / Apptainer (common on HPC clusters)
		{Pattern: "*/.apptainer/cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Apptainer/Singularity image layer cache (~500MB–20GB, common on HPC)",
			Action:      Action{Type: "command", Command: "apptainer cache clean --force", Shell: "bash"}},
		{Pattern: "*/.singularity/cache", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Singularity image layer cache (legacy path)",
			Action:      Action{Type: "command", Command: "singularity cache clean --force", Shell: "bash"}},

		// Flatpak
		{Pattern: "/var/tmp/flatpak-cache*", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Flatpak temporary cache",
			Action:      Action{Type: "manual", Hint: "Delete flatpak cache"}},
		{Pattern: "*/.cache/flatpak", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Description: "Flatpak user cache",
			Action:      Action{Type: "manual", Hint: "rm -rf ~/.cache/flatpak"}},

		// ── Logs ──────────────────────────────────────────────────────────────

		// Journal logs
		{Pattern: "/var/log", Kind: KindLog, Risk: RiskSafe, Platform: "linux",
			Description: "System logs (journalctl)",
			Action:      Action{Type: "command", Command: "sudo journalctl --vacuum-time=7d", Shell: "bash"}},

		// Rotated logs
		{Pattern: "/var/log/*.gz", Kind: KindLog, Risk: RiskSafe, Platform: "linux",
			Description: "Compressed rotated log files",
			Action:      Action{Type: "command", Command: "sudo find /var/log -name '*.gz' -delete", Shell: "bash"}},

		// App logs in ~/.local/share
		{Pattern: "*/.local/share/*/logs", Kind: KindLog, Risk: RiskSafe, Platform: "linux",
			Description: "Application log files (Discord, Slack, etc.)",
			Action:      Action{Type: "manual", Hint: "find ~/.local/share -name '*.log' -mtime +30 -delete"}},

		// ── Misc ──────────────────────────────────────────────────────────────

		// Trash
		{Pattern: "*/.local/share/Trash", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "User trash (deleted files)",
			Action:      Action{Type: "manual", Hint: "Empty trash"}},

		// Thumbnails
		{Pattern: "*/.cache/thumbnails", Kind: KindCache, Risk: RiskSafe, Platform: "linux",
			Cosmetic:    true,
			Description: "Image thumbnail cache (regenerates on folder browse)",
			Action:      Action{Type: "manual", Hint: "Delete thumbnails, will regenerate"}},

		// Core dumps / crash reports
		{Pattern: "/var/crash", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "Crash reports",
			Action:      Action{Type: "command", Command: "sudo rm -f /var/crash/*", Shell: "bash"}},
		{Pattern: "/var/lib/apport/coredump", Kind: KindTemp, Risk: RiskSafe, Platform: "linux",
			Description: "Apport core dump archives",
			Action:      Action{Type: "command", Command: "sudo rm -f /var/lib/apport/coredump/*", Shell: "bash"}},
	}
}
