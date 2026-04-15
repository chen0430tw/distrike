package hunter

// Rule defines a pattern for identifying prey.
type Rule struct {
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Kind        PreyKind `yaml:"kind" json:"kind"`
	Risk        Risk     `yaml:"risk" json:"risk"`
	Platform    string   `yaml:"platform" json:"platform"`
	Description string   `yaml:"description" json:"description"`
	Action      Action   `yaml:"action" json:"action"`
}

// BuiltinRules returns all built-in prey identification rules.
// Rules are organized by platform and category.
func BuiltinRules() []Rule {
	var rules []Rule
	rules = append(rules, commonCacheRules()...)
	rules = append(rules, platformRules()...)
	return rules
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
