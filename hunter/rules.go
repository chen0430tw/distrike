package hunter

// Rule defines a pattern for identifying prey.
type Rule struct {
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Kind        PreyKind `yaml:"kind" json:"kind"`
	Risk        Risk     `yaml:"risk" json:"risk"`
	Platform    string   `yaml:"platform" json:"platform"`
	Description string   `yaml:"description" json:"description"`
	Action      Action   `yaml:"action" json:"action"`
	// Cosmetic marks rules whose items are typically <1 MB or auto-regenerate immediately.
	// Useful for tools like CCleaner that include these for completeness, but real impact is negligible.
	Cosmetic bool `yaml:"cosmetic,omitempty" json:"cosmetic,omitempty"`
}

// BuiltinRules returns all built-in prey identification rules.
// Rules are organized by platform and category.
//
// Rule sources, in match-priority order (matcher returns the FIRST match):
//  1. commonCacheRules        — cross-platform package managers, IDE caches, etc.
//  2. platformRules           — hand-curated per-OS rules (rules_{windows,linux,darwin}.go)
//  3. platformDiscoveredRules — runtime-discovered (currently: Windows VolumeCaches
//                               registry — same source SilentCleanup uses; nil on
//                               other platforms)
//
// Hand-curated rules win on overlap, so a registry-discovered "Temporary Files"
// handler won't override the more accurate built-in "*/AppData/Local/Temp" rule.
func BuiltinRules() []Rule {
	var rules []Rule
	rules = append(rules, commonCacheRules()...)
	rules = append(rules, platformRules()...)
	rules = append(rules, platformDiscoveredRules()...)
	return rules
}

// ModelWeightRules returns rules for detecting large model weight files.
// These are NOT included in BuiltinRules — enabled via hunt.scan_model_weights = true.
func ModelWeightRules() []Rule {
	return []Rule{
		// ── File-extension rules (matches any file with this extension) ──────

		// safetensors — HuggingFace standard format, always model weights
		{Pattern: "*.safetensors", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "HuggingFace safetensors model weight file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},

		// GGUF / GGML — llama.cpp quantized models (1–70 GB each)
		{Pattern: "*.gguf", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "llama.cpp GGUF quantized model weight file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},
		{Pattern: "*.ggml", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "llama.cpp GGML model weight file (legacy format)",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},

		// PyTorch weights / checkpoints
		{Pattern: "*.pt", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "PyTorch model weight or checkpoint file",
			Action:      Action{Type: "manual", Hint: "Check if this is a training checkpoint or final weights"}},
		{Pattern: "*.pth", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "PyTorch model state dict file",
			Action:      Action{Type: "manual", Hint: "Check if this is a training checkpoint or final weights"}},

		// TensorFlow / Keras / Lightning checkpoints
		{Pattern: "*.ckpt", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "TensorFlow/PyTorch Lightning checkpoint file",
			Action:      Action{Type: "manual", Hint: "Keep latest checkpoint; remove older ones if training is done"}},
		{Pattern: "*.h5", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "Keras/HDF5 model weight file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},
		{Pattern: "*.hdf5", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "HDF5 model weight file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},

		// ONNX — exported inference models
		{Pattern: "*.onnx", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "ONNX exported model file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},

		// TensorFlow SavedModel bin shard
		{Pattern: "*.pb", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "TensorFlow SavedModel / protobuf model file",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},

		// ── Directory-level rules ─────────────────────────────────────────────

		// HuggingFace hub snapshot dirs (each snapshot is one model version)
		{Pattern: "*/snapshots", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "HuggingFace hub model version snapshots (old versions safe to remove)",
			Action:      Action{Type: "manual", Hint: "huggingface-cli delete-cache to remove unused revisions"}},

		// Common checkpoint output directories from training runs
		{Pattern: "*/checkpoints", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "Training checkpoint directory (verify training is complete before deleting)",
			Action:      Action{Type: "manual", Hint: "Keep latest checkpoint; remove older step checkpoints"}},

		// Weights-only subdirs
		{Pattern: "*/weights", Kind: KindModel, Risk: RiskCaution, Platform: "all",
			Description: "Model weights directory",
			Action:      Action{Type: "manual", Hint: "Verify model is no longer needed before deleting"}},
	}
}

func commonCacheRules() []Rule {
	return []Rule{
		{Pattern: "*/pip/cache", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Python pip package cache",
			Action:      Action{Type: "command", Command: "pip cache purge"}},
		{Pattern: "*/npm-cache", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "npm package cache",
			Action:      Action{Type: "command", Command: "npm cache clean --force"}},
		{Pattern: "*/yarn/cache", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Yarn package cache",
			Action:      Action{Type: "command", Command: "yarn cache clean"}},
		{Pattern: "*/.cache/go-build", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Go build cache",
			Action:      Action{Type: "command", Command: "go clean -cache"}},
		{Pattern: "*/.cargo/registry", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Rust crate cache (skip: distrike config whitelist add ~/.cargo/registry)",
			Action:      Action{Type: "manual", Hint: "Delete registry/cache contents, cargo will re-download on demand"}},
		{Pattern: "*/.gradle/caches", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Gradle build cache",
			Action:      Action{Type: "manual", Hint: "Delete contents of .gradle/caches/"}},
		{Pattern: "*/conda/pkgs", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Conda package cache",
			Action:      Action{Type: "command", Command: "conda clean --all -y"}},
		{Pattern: "*/huggingface/hub", Kind: KindCache, Risk: RiskCaution, Platform: "all",
			Description: "HuggingFace model cache",
			Action:      Action{Type: "command", Command: "huggingface-cli delete-cache"}},
		{Pattern: "*/torch/hub", Kind: KindCache, Risk: RiskCaution, Platform: "all",
			Description: "PyTorch model cache",
			Action:      Action{Type: "manual", Hint: "Delete contents of torch/hub/"}},

		// Node.js
		{Pattern: "*/node_modules", Kind: KindCache, Risk: RiskCaution, Platform: "all",
			Description: "Node.js dependencies (can be reinstalled with npm/yarn install)",
			Action:      Action{Type: "manual", Hint: "Delete and run npm install to restore"}},
		{Pattern: "*/.next/cache", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Next.js build cache",
			Action:      Action{Type: "manual", Hint: "Delete .next/cache"}},

		// Python
		{Pattern: "*/.tox", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "tox virtualenv cache",
			Action:      Action{Type: "manual", Hint: "Delete .tox directory"}},
		{Pattern: "*/.venv", Kind: KindCache, Risk: RiskCaution, Platform: "all",
			Description: "Python virtual environment",
			Action:      Action{Type: "manual", Hint: "Delete and recreate with python -m venv .venv"}},
		// NOTE: */dist is too broad — matches VS Code extensions, Copilot, etc.
		// Only match dist at project root level, not deep inside installed packages.

		// .NET
		{Pattern: "*/.nuget/packages", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "NuGet package cache",
			Action:      Action{Type: "command", Command: "dotnet nuget locals all --clear"}},
		{Pattern: "*/bin/Debug", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: ".NET debug build output",
			Action:      Action{Type: "manual", Hint: "Delete bin/Debug, rebuild when needed"}},
		{Pattern: "*/bin/Release", Kind: KindCache, Risk: RiskCaution, Platform: "all",
			Description: ".NET release build output",
			Action:      Action{Type: "manual", Hint: "Delete bin/Release if not deployed"}},

		// Maven
		{Pattern: "*/.m2/repository", Kind: KindCache, Risk: RiskSafe, Platform: "all",
			Description: "Maven local repository cache",
			Action:      Action{Type: "manual", Hint: "Delete and Maven will re-download dependencies"}},
	}
}

// platformRules returns platform-specific rules.
// Actual implementations in rules_windows.go, rules_darwin.go, rules_linux.go
func platformRules() []Rule {
	return platformSpecificRules()
}
