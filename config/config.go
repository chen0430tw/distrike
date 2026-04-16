package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"distrike/internal/units"

	"gopkg.in/yaml.v3"
)

// Config holds all Distrike configuration.
type Config struct {
	KillLine          string            `yaml:"kill_line"`
	SafeMultiplier    float64           `yaml:"safe_multiplier"`
	KillLineOverrides map[string]string `yaml:"kill_line_overrides,omitempty"`

	Signal   SignalConfig   `yaml:"signal"`
	Health   HealthConfig   `yaml:"health"`
	Security SecurityConfig `yaml:"security"`
	Scan     ScanConfig     `yaml:"scan"`
	Cache    CacheConfig    `yaml:"cache"`
	Hunt     HuntConfig     `yaml:"hunt"`
	Clean    CleanConfig    `yaml:"clean"`
	Docker   DockerConfig   `yaml:"docker"`
	WSL      WSLConfig      `yaml:"wsl"`
	VDisk    VDiskConfig    `yaml:"vdisk"`
	Watch    WatchConfig    `yaml:"watch"`
	Output   OutputConfig   `yaml:"output"`

	Whitelist   []string     `yaml:"whitelist"`
	CustomRules []RuleConfig `yaml:"custom_rules"`
}

type SignalConfig struct {
	Enabled           bool             `yaml:"enabled"`
	Thresholds        ThresholdConfig  `yaml:"thresholds"`
	RiskWeights       RiskWeightConfig `yaml:"risk_weights"`
	ConcentrationTopN int              `yaml:"concentration_top_n"`
}

type ThresholdConfig struct {
	Purple ThresholdLevel `yaml:"purple"`
	Red    ThresholdLevel `yaml:"red"`
	Yellow ThresholdLevel `yaml:"yellow"`
}

type ThresholdLevel struct {
	UsedRatio             float64 `yaml:"used_ratio"`
	Concentration         float64 `yaml:"concentration"`
	RequiresBelowKillLine bool    `yaml:"requires_below_kill_line,omitempty"`
	Logic                 string  `yaml:"logic,omitempty"` // "and" (default) or "or"
}

type RiskWeightConfig struct {
	UsedRatio     float64 `yaml:"used_ratio"`
	Concentration float64 `yaml:"concentration"`
}

type HealthConfig struct {
	Enabled         bool `yaml:"enabled"`
	SMART           struct {
		Enabled bool   `yaml:"enabled"`
		Path    string `yaml:"path"`
	} `yaml:"smart"`
	CapacityAnomaly struct {
		Enabled       bool    `yaml:"enabled"`
		RemovableOnly bool    `yaml:"removable_only"`
		Threshold     float64 `yaml:"threshold"`
	} `yaml:"capacity_anomaly"`
	BadSectors struct {
		Enabled       bool `yaml:"enabled"`
		WarnThreshold int  `yaml:"warn_threshold"`
		CritThreshold int  `yaml:"crit_threshold"`
	} `yaml:"bad_sectors"`
	WearLevel struct {
		Enabled bool `yaml:"enabled"`
		WarnPct int  `yaml:"warn_pct"`
		CritPct int  `yaml:"crit_pct"`
	} `yaml:"wear_level"`
	FSErrors struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"fs_errors"`
}

type SecurityConfig struct {
	Encryption struct {
		Detect               bool `yaml:"detect"`
		IncludeLockedInSignal bool `yaml:"include_locked_in_signal"`
	} `yaml:"encryption"`
	AccessDeniedPolicy string  `yaml:"access_denied_policy"`
	MinCoverageWarning float64 `yaml:"min_coverage_warning"`
}

type ScanConfig struct {
	MaxDepth       int      `yaml:"max_depth"`
	MinSize        string   `yaml:"min_size"`
	Top            int      `yaml:"top"`
	FollowSymlinks bool     `yaml:"follow_symlinks"`
	Engine         string   `yaml:"engine"`
	StorageMode    string   `yaml:"storage_mode"`
	Workers        int      `yaml:"workers"`
	Exclude        []string `yaml:"exclude"`
}

type CacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	TTL     string `yaml:"ttl"`
	Path    string `yaml:"path"`
	MaxSize string `yaml:"max_size"`
}

type HuntConfig struct {
	BuiltinRules      bool            `yaml:"builtin_rules"`
	DefaultRiskFilter string          `yaml:"default_risk_filter"`
	MinPreySize       string          `yaml:"min_prey_size"`
	Categories        map[string]bool `yaml:"categories"`
	ScanModelWeights  bool            `yaml:"scan_model_weights"`
}

type CleanConfig struct {
	Confirm          bool `yaml:"confirm"`
	VerifyAfterClean bool `yaml:"verify_after_clean"`
	History          bool `yaml:"history"`
	MaxHistory       int  `yaml:"max_history"`
}

type DockerConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Executable       string `yaml:"executable"`
	StoppedThreshold string `yaml:"stopped_threshold"`
}

type WSLConfig struct {
	Enabled                bool   `yaml:"enabled"`
	DetectVHDX             bool   `yaml:"detect_vhdx"`
	SparseSuggestThreshold string `yaml:"sparse_suggest_threshold"`
	AutoFSTrim             bool   `yaml:"auto_fstrim"`
}

type VDiskConfig struct {
	Enabled bool   `yaml:"enabled"`
	MinSize string `yaml:"min_size"`
}

type WatchConfig struct {
	PurpleInterval string `yaml:"purple_interval"` // < 1GB (default 10s)
	RedInterval    string `yaml:"red_interval"`    // < kill_line (default 30s)
	YellowInterval string `yaml:"yellow_interval"` // < kill_line*1.5 (default 5m)
	GreenInterval  string `yaml:"green_interval"`  // safe (default 15m)
}

type OutputConfig struct {
	Format     string `yaml:"format"`
	Progress   bool   `yaml:"progress"`
	Color      string `yaml:"color"`
	JSONIndent bool   `yaml:"json_indent"`
	TimeFormat string `yaml:"time_format"`
}

type RuleConfig struct {
	Pattern     string `yaml:"pattern"`
	Kind        string `yaml:"kind"`
	Risk        string `yaml:"risk"`
	Platform    string `yaml:"platform"`
	Description string `yaml:"description"`
	Action      struct {
		Type    string `yaml:"type"`
		Command string `yaml:"command,omitempty"`
		Hint    string `yaml:"hint,omitempty"`
	} `yaml:"action"`
}

// DefaultConfigPath returns the platform-specific config file path.
func DefaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "distrike", "config.yaml")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "distrike", "config.yaml")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "distrike", "config.yaml")
	}
}

// Load reads config from the default path, creating defaults if missing.
func Load() (*Config, error) {
	return LoadFrom(DefaultConfigPath())
}

// LoadFrom reads config from the specified path, creating defaults if missing.
func LoadFrom(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist — save defaults and return
			if saveErr := SaveTo(cfg, path); saveErr != nil {
				// Can't save defaults (e.g. dir doesn't exist yet) — just return defaults
				return cfg, nil
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Parse YAML into config (defaults already set, so missing fields keep defaults)
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return cfg, nil
}

// Save writes config to the default path.
func Save(cfg *Config) error {
	return SaveTo(cfg, DefaultConfigPath())
}

// SaveTo writes config to the specified path.
func SaveTo(cfg *Config, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}

	return nil
}

// Set sets a config value by dotted key path (e.g. "scan.max_depth").
func Set(cfg *Config, key, value string) error {
	parts := strings.Split(key, ".")

	switch len(parts) {
	case 1:
		return setTopLevel(cfg, parts[0], value)
	case 2:
		return setNested(cfg, parts[0], parts[1], value)
	case 3:
		return setDeepNested(cfg, parts[0], parts[1], parts[2], value)
	default:
		return fmt.Errorf("unsupported key depth: %q", key)
	}
}

// Get retrieves a config value by dotted key path.
func Get(cfg *Config, key string) (string, error) {
	parts := strings.Split(key, ".")

	switch len(parts) {
	case 1:
		return getTopLevel(cfg, parts[0])
	case 2:
		return getNested(cfg, parts[0], parts[1])
	case 3:
		return getDeepNested(cfg, parts[0], parts[1], parts[2])
	default:
		return "", fmt.Errorf("unsupported key depth: %q", key)
	}
}

func setTopLevel(cfg *Config, key, value string) error {
	switch key {
	case "kill_line":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		cfg.KillLine = value
	case "safe_multiplier":
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float %q: %w", value, err)
		}
		cfg.SafeMultiplier = v
	default:
		return fmt.Errorf("unknown top-level key: %q", key)
	}
	return nil
}

func getTopLevel(cfg *Config, key string) (string, error) {
	switch key {
	case "kill_line":
		return cfg.KillLine, nil
	case "safe_multiplier":
		return strconv.FormatFloat(cfg.SafeMultiplier, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unknown top-level key: %q", key)
	}
}

func setNested(cfg *Config, section, key, value string) error {
	switch section {
	case "scan":
		return setScan(&cfg.Scan, key, value)
	case "cache":
		return setCache(&cfg.Cache, key, value)
	case "hunt":
		return setHunt(&cfg.Hunt, key, value)
	case "clean":
		return setClean(&cfg.Clean, key, value)
	case "docker":
		return setDocker(&cfg.Docker, key, value)
	case "wsl":
		return setWSL(&cfg.WSL, key, value)
	case "vdisk":
		return setVDisk(&cfg.VDisk, key, value)
	case "output":
		return setOutput(&cfg.Output, key, value)
	case "signal":
		return setSignal(&cfg.Signal, key, value)
	case "health":
		return setHealth(&cfg.Health, key, value)
	case "security":
		return setSecurity(&cfg.Security, key, value)
	default:
		return fmt.Errorf("unknown section: %q", section)
	}
}

func getNested(cfg *Config, section, key string) (string, error) {
	switch section {
	case "scan":
		return getScan(&cfg.Scan, key)
	case "cache":
		return getCache(&cfg.Cache, key)
	case "hunt":
		return getHunt(&cfg.Hunt, key)
	case "clean":
		return getClean(&cfg.Clean, key)
	case "docker":
		return getDocker(&cfg.Docker, key)
	case "wsl":
		return getWSL(&cfg.WSL, key)
	case "vdisk":
		return getVDisk(&cfg.VDisk, key)
	case "output":
		return getOutput(&cfg.Output, key)
	case "signal":
		return getSignal(&cfg.Signal, key)
	case "health":
		return getHealth(&cfg.Health, key)
	case "security":
		return getSecurity(&cfg.Security, key)
	default:
		return "", fmt.Errorf("unknown section: %q", section)
	}
}

func setDeepNested(cfg *Config, section, sub, key, value string) error {
	switch section {
	case "signal":
		if sub == "thresholds" {
			return fmt.Errorf("use 'signal.thresholds.<color>.<field>' for threshold config")
		}
		if sub == "risk_weights" {
			return setRiskWeights(&cfg.Signal.RiskWeights, key, value)
		}
	case "health":
		return setHealthSub(&cfg.Health, sub, key, value)
	case "security":
		if sub == "encryption" {
			return setEncryption(&cfg.Security.Encryption, key, value)
		}
	}
	return fmt.Errorf("unknown nested key: %s.%s.%s", section, sub, key)
}

func getDeepNested(cfg *Config, section, sub, key string) (string, error) {
	switch section {
	case "signal":
		if sub == "risk_weights" {
			return getRiskWeights(&cfg.Signal.RiskWeights, key)
		}
	case "health":
		return getHealthSub(&cfg.Health, sub, key)
	case "security":
		if sub == "encryption" {
			return getEncryption(&cfg.Security.Encryption, key)
		}
	}
	return "", fmt.Errorf("unknown nested key: %s.%s.%s", section, sub, key)
}

// --- Scan ---

func setScan(s *ScanConfig, key, value string) error {
	switch key {
	case "max_depth":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", value, err)
		}
		s.MaxDepth = v
	case "min_size":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		s.MinSize = value
	case "top":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", value, err)
		}
		s.Top = v
	case "follow_symlinks":
		s.FollowSymlinks = parseBool(value)
	case "engine":
		s.Engine = value
	case "storage_mode":
		s.StorageMode = value
	case "workers":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", value, err)
		}
		s.Workers = v
	default:
		return fmt.Errorf("unknown scan key: %q", key)
	}
	return nil
}

func getScan(s *ScanConfig, key string) (string, error) {
	switch key {
	case "max_depth":
		return strconv.Itoa(s.MaxDepth), nil
	case "min_size":
		return s.MinSize, nil
	case "top":
		return strconv.Itoa(s.Top), nil
	case "follow_symlinks":
		return strconv.FormatBool(s.FollowSymlinks), nil
	case "engine":
		return s.Engine, nil
	case "storage_mode":
		return s.StorageMode, nil
	case "workers":
		return strconv.Itoa(s.Workers), nil
	default:
		return "", fmt.Errorf("unknown scan key: %q", key)
	}
}

// --- Cache ---

func setCache(c *CacheConfig, key, value string) error {
	switch key {
	case "enabled":
		c.Enabled = parseBool(value)
	case "ttl":
		c.TTL = value
	case "path":
		c.Path = value
	case "max_size":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		c.MaxSize = value
	default:
		return fmt.Errorf("unknown cache key: %q", key)
	}
	return nil
}

func getCache(c *CacheConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(c.Enabled), nil
	case "ttl":
		return c.TTL, nil
	case "path":
		return c.Path, nil
	case "max_size":
		return c.MaxSize, nil
	default:
		return "", fmt.Errorf("unknown cache key: %q", key)
	}
}

// --- Hunt ---

func setHunt(h *HuntConfig, key, value string) error {
	switch key {
	case "builtin_rules":
		h.BuiltinRules = parseBool(value)
	case "default_risk_filter":
		h.DefaultRiskFilter = value
	case "min_prey_size":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		h.MinPreySize = value
	case "scan_model_weights":
		h.ScanModelWeights = parseBool(value)
	default:
		return fmt.Errorf("unknown hunt key: %q", key)
	}
	return nil
}

func getHunt(h *HuntConfig, key string) (string, error) {
	switch key {
	case "builtin_rules":
		return strconv.FormatBool(h.BuiltinRules), nil
	case "default_risk_filter":
		return h.DefaultRiskFilter, nil
	case "min_prey_size":
		return h.MinPreySize, nil
	case "scan_model_weights":
		return strconv.FormatBool(h.ScanModelWeights), nil
	default:
		return "", fmt.Errorf("unknown hunt key: %q", key)
	}
}

// --- Clean ---

func setClean(c *CleanConfig, key, value string) error {
	switch key {
	case "confirm":
		c.Confirm = parseBool(value)
	case "verify_after_clean":
		c.VerifyAfterClean = parseBool(value)
	case "history":
		c.History = parseBool(value)
	case "max_history":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", value, err)
		}
		c.MaxHistory = v
	default:
		return fmt.Errorf("unknown clean key: %q", key)
	}
	return nil
}

func getClean(c *CleanConfig, key string) (string, error) {
	switch key {
	case "confirm":
		return strconv.FormatBool(c.Confirm), nil
	case "verify_after_clean":
		return strconv.FormatBool(c.VerifyAfterClean), nil
	case "history":
		return strconv.FormatBool(c.History), nil
	case "max_history":
		return strconv.Itoa(c.MaxHistory), nil
	default:
		return "", fmt.Errorf("unknown clean key: %q", key)
	}
}

// --- Docker ---

func setDocker(d *DockerConfig, key, value string) error {
	switch key {
	case "enabled":
		d.Enabled = parseBool(value)
	case "executable":
		d.Executable = value
	case "stopped_threshold":
		d.StoppedThreshold = value
	default:
		return fmt.Errorf("unknown docker key: %q", key)
	}
	return nil
}

func getDocker(d *DockerConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(d.Enabled), nil
	case "executable":
		return d.Executable, nil
	case "stopped_threshold":
		return d.StoppedThreshold, nil
	default:
		return "", fmt.Errorf("unknown docker key: %q", key)
	}
}

// --- WSL ---

func setWSL(w *WSLConfig, key, value string) error {
	switch key {
	case "enabled":
		w.Enabled = parseBool(value)
	case "detect_vhdx":
		w.DetectVHDX = parseBool(value)
	case "sparse_suggest_threshold":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		w.SparseSuggestThreshold = value
	case "auto_fstrim":
		w.AutoFSTrim = parseBool(value)
	default:
		return fmt.Errorf("unknown wsl key: %q", key)
	}
	return nil
}

func getWSL(w *WSLConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(w.Enabled), nil
	case "detect_vhdx":
		return strconv.FormatBool(w.DetectVHDX), nil
	case "sparse_suggest_threshold":
		return w.SparseSuggestThreshold, nil
	case "auto_fstrim":
		return strconv.FormatBool(w.AutoFSTrim), nil
	default:
		return "", fmt.Errorf("unknown wsl key: %q", key)
	}
}

// --- VDisk ---

func setVDisk(v *VDiskConfig, key, value string) error {
	switch key {
	case "enabled":
		v.Enabled = parseBool(value)
	case "min_size":
		if _, err := units.ParseSize(value); err != nil {
			return fmt.Errorf("invalid size %q: %w", value, err)
		}
		v.MinSize = value
	default:
		return fmt.Errorf("unknown vdisk key: %q", key)
	}
	return nil
}

func getVDisk(v *VDiskConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(v.Enabled), nil
	case "min_size":
		return v.MinSize, nil
	default:
		return "", fmt.Errorf("unknown vdisk key: %q", key)
	}
}

// --- Output ---

func setOutput(o *OutputConfig, key, value string) error {
	switch key {
	case "format":
		o.Format = value
	case "progress":
		o.Progress = parseBool(value)
	case "color":
		o.Color = value
	case "json_indent":
		o.JSONIndent = parseBool(value)
	case "time_format":
		o.TimeFormat = value
	default:
		return fmt.Errorf("unknown output key: %q", key)
	}
	return nil
}

func getOutput(o *OutputConfig, key string) (string, error) {
	switch key {
	case "format":
		return o.Format, nil
	case "progress":
		return strconv.FormatBool(o.Progress), nil
	case "color":
		return o.Color, nil
	case "json_indent":
		return strconv.FormatBool(o.JSONIndent), nil
	case "time_format":
		return o.TimeFormat, nil
	default:
		return "", fmt.Errorf("unknown output key: %q", key)
	}
}

// --- Signal ---

func setSignal(s *SignalConfig, key, value string) error {
	switch key {
	case "enabled":
		s.Enabled = parseBool(value)
	case "concentration_top_n":
		v, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", value, err)
		}
		s.ConcentrationTopN = v
	default:
		return fmt.Errorf("unknown signal key: %q", key)
	}
	return nil
}

func getSignal(s *SignalConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(s.Enabled), nil
	case "concentration_top_n":
		return strconv.Itoa(s.ConcentrationTopN), nil
	default:
		return "", fmt.Errorf("unknown signal key: %q", key)
	}
}

// --- Signal Risk Weights ---

func setRiskWeights(r *RiskWeightConfig, key, value string) error {
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fmt.Errorf("invalid float %q: %w", value, err)
	}
	switch key {
	case "used_ratio":
		r.UsedRatio = v
	case "concentration":
		r.Concentration = v
	default:
		return fmt.Errorf("unknown risk_weights key: %q", key)
	}
	return nil
}

func getRiskWeights(r *RiskWeightConfig, key string) (string, error) {
	switch key {
	case "used_ratio":
		return strconv.FormatFloat(r.UsedRatio, 'f', -1, 64), nil
	case "concentration":
		return strconv.FormatFloat(r.Concentration, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unknown risk_weights key: %q", key)
	}
}

// --- Health ---

func setHealth(h *HealthConfig, key, value string) error {
	switch key {
	case "enabled":
		h.Enabled = parseBool(value)
	default:
		return fmt.Errorf("unknown health key: %q", key)
	}
	return nil
}

func getHealth(h *HealthConfig, key string) (string, error) {
	switch key {
	case "enabled":
		return strconv.FormatBool(h.Enabled), nil
	default:
		return "", fmt.Errorf("unknown health key: %q", key)
	}
}

func setHealthSub(h *HealthConfig, sub, key, value string) error {
	switch sub {
	case "smart":
		switch key {
		case "enabled":
			h.SMART.Enabled = parseBool(value)
		case "path":
			h.SMART.Path = value
		default:
			return fmt.Errorf("unknown health.smart key: %q", key)
		}
	case "capacity_anomaly":
		switch key {
		case "enabled":
			h.CapacityAnomaly.Enabled = parseBool(value)
		case "removable_only":
			h.CapacityAnomaly.RemovableOnly = parseBool(value)
		case "threshold":
			v, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("invalid float %q: %w", value, err)
			}
			h.CapacityAnomaly.Threshold = v
		default:
			return fmt.Errorf("unknown health.capacity_anomaly key: %q", key)
		}
	case "bad_sectors":
		switch key {
		case "enabled":
			h.BadSectors.Enabled = parseBool(value)
		case "warn_threshold":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid int %q: %w", value, err)
			}
			h.BadSectors.WarnThreshold = v
		case "crit_threshold":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid int %q: %w", value, err)
			}
			h.BadSectors.CritThreshold = v
		default:
			return fmt.Errorf("unknown health.bad_sectors key: %q", key)
		}
	case "wear_level":
		switch key {
		case "enabled":
			h.WearLevel.Enabled = parseBool(value)
		case "warn_pct":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid int %q: %w", value, err)
			}
			h.WearLevel.WarnPct = v
		case "crit_pct":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid int %q: %w", value, err)
			}
			h.WearLevel.CritPct = v
		default:
			return fmt.Errorf("unknown health.wear_level key: %q", key)
		}
	case "fs_errors":
		switch key {
		case "enabled":
			h.FSErrors.Enabled = parseBool(value)
		default:
			return fmt.Errorf("unknown health.fs_errors key: %q", key)
		}
	default:
		return fmt.Errorf("unknown health subsection: %q", sub)
	}
	return nil
}

func getHealthSub(h *HealthConfig, sub, key string) (string, error) {
	switch sub {
	case "smart":
		switch key {
		case "enabled":
			return strconv.FormatBool(h.SMART.Enabled), nil
		case "path":
			return h.SMART.Path, nil
		default:
			return "", fmt.Errorf("unknown health.smart key: %q", key)
		}
	case "capacity_anomaly":
		switch key {
		case "enabled":
			return strconv.FormatBool(h.CapacityAnomaly.Enabled), nil
		case "removable_only":
			return strconv.FormatBool(h.CapacityAnomaly.RemovableOnly), nil
		case "threshold":
			return strconv.FormatFloat(h.CapacityAnomaly.Threshold, 'f', -1, 64), nil
		default:
			return "", fmt.Errorf("unknown health.capacity_anomaly key: %q", key)
		}
	case "bad_sectors":
		switch key {
		case "enabled":
			return strconv.FormatBool(h.BadSectors.Enabled), nil
		case "warn_threshold":
			return strconv.Itoa(h.BadSectors.WarnThreshold), nil
		case "crit_threshold":
			return strconv.Itoa(h.BadSectors.CritThreshold), nil
		default:
			return "", fmt.Errorf("unknown health.bad_sectors key: %q", key)
		}
	case "wear_level":
		switch key {
		case "enabled":
			return strconv.FormatBool(h.WearLevel.Enabled), nil
		case "warn_pct":
			return strconv.Itoa(h.WearLevel.WarnPct), nil
		case "crit_pct":
			return strconv.Itoa(h.WearLevel.CritPct), nil
		default:
			return "", fmt.Errorf("unknown health.wear_level key: %q", key)
		}
	case "fs_errors":
		switch key {
		case "enabled":
			return strconv.FormatBool(h.FSErrors.Enabled), nil
		default:
			return "", fmt.Errorf("unknown health.fs_errors key: %q", key)
		}
	default:
		return "", fmt.Errorf("unknown health subsection: %q", sub)
	}
}

// --- Security ---

func setSecurity(s *SecurityConfig, key, value string) error {
	switch key {
	case "access_denied_policy":
		s.AccessDeniedPolicy = value
	case "min_coverage_warning":
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float %q: %w", value, err)
		}
		s.MinCoverageWarning = v
	default:
		return fmt.Errorf("unknown security key: %q", key)
	}
	return nil
}

func getSecurity(s *SecurityConfig, key string) (string, error) {
	switch key {
	case "access_denied_policy":
		return s.AccessDeniedPolicy, nil
	case "min_coverage_warning":
		return strconv.FormatFloat(s.MinCoverageWarning, 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("unknown security key: %q", key)
	}
}

// --- Security Encryption ---

func setEncryption(e *struct {
	Detect                bool `yaml:"detect"`
	IncludeLockedInSignal bool `yaml:"include_locked_in_signal"`
}, key, value string) error {
	switch key {
	case "detect":
		e.Detect = parseBool(value)
	case "include_locked_in_signal":
		e.IncludeLockedInSignal = parseBool(value)
	default:
		return fmt.Errorf("unknown security.encryption key: %q", key)
	}
	return nil
}

func getEncryption(e *struct {
	Detect                bool `yaml:"detect"`
	IncludeLockedInSignal bool `yaml:"include_locked_in_signal"`
}, key string) (string, error) {
	switch key {
	case "detect":
		return strconv.FormatBool(e.Detect), nil
	case "include_locked_in_signal":
		return strconv.FormatBool(e.IncludeLockedInSignal), nil
	default:
		return "", fmt.Errorf("unknown security.encryption key: %q", key)
	}
}

// parseBool parses common boolean strings.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// DefaultConfig returns a Config with all defaults set.
func DefaultConfig() *Config {
	return &Config{
		KillLine:       "20GB",
		SafeMultiplier: 2.0,
		Signal: SignalConfig{
			Enabled: true,
			Thresholds: ThresholdConfig{
				Purple: ThresholdLevel{UsedRatio: 0.90, Concentration: 0.60, RequiresBelowKillLine: true},
				Red:    ThresholdLevel{UsedRatio: 0.85, Concentration: 0.50},
				Yellow: ThresholdLevel{UsedRatio: 0.70, Concentration: 0.35, Logic: "or"},
			},
			RiskWeights:       RiskWeightConfig{UsedRatio: 60, Concentration: 40},
			ConcentrationTopN: 10,
		},
		Health: HealthConfig{Enabled: true},
		// Whitelist principle: protect ONLY data that has no copy elsewhere and
		// cannot be recovered if deleted. Re-downloadable caches (chat images,
		// video previews) are NOT whitelisted — they appear as CAUTION prey so
		// users can make an informed decision. Hiding them denies users the
		// information they need and prevents them from learning the cost.
		//
		// Criterion: is there a server-side copy?
		//   nt_db / Msg databases → local-only, unrecoverable → whitelist ✅
		//   FileRecv / FileStorage → user explicitly saved → whitelist ✅
		//   nt_data/Pic, Video → QQ/WeChat server backup exists → CAUTION, not whitelist
		Whitelist: []string{
			// WeChat — message data and user-saved files only
			"*/WeChat Files/*/Msg",         // message databases (MsgAttach, Multi) — local only
			"*/WeChat Files/*/FileStorage", // files the user explicitly saved — local only
			"*/WeChat Files/*/BackupFiles", // chat backups — local only
			// QQ / QQNT — message databases and explicitly received files only
			"*/Tencent Files/*/FileRecv",   // files user explicitly received/saved — local only
			"*/Tencent Files/*/Msg3.0.db",  // classic QQ message database — local only
			"*/QQNT/*/nt_db",              // QQNT message database — local only
			// NOT whitelisted (server-side copy exists, shown as CAUTION prey):
			//   nt_data/Pic, nt_data/Video, nt_data/Emoji
			//   WeChat Files/*/Image, WeChat Files/*/Video
		},
		Scan: ScanConfig{
			MaxDepth: 3, MinSize: "100MB", Top: 20,
			Engine: "auto", StorageMode: "auto",
			Exclude: []string{"$RECYCLE.BIN", "System Volume Information", ".git", "node_modules",
				"/proc", "/sys", "/dev", "/run"},
		},
		Cache:  CacheConfig{Enabled: true, TTL: "1h", Path: "auto", MaxSize: "100MB"},
		Hunt: HuntConfig{BuiltinRules: true, DefaultRiskFilter: "all", MinPreySize: "50MB",
			ScanModelWeights: false,
			Categories: map[string]bool{"cache": true, "temp": true, "vdisk": true,
				"backup": true, "download": true, "orphan": true, "log": true, "model": false}},
		Clean:  CleanConfig{Confirm: true, VerifyAfterClean: true, History: true, MaxHistory: 100},
		Docker: DockerConfig{Enabled: true, Executable: "auto", StoppedThreshold: "7d"},
		WSL:    WSLConfig{Enabled: true, DetectVHDX: true, SparseSuggestThreshold: "10GB", AutoFSTrim: true},
		Watch:  WatchConfig{PurpleInterval: "10s", RedInterval: "30s", YellowInterval: "5m", GreenInterval: "15m"},
		VDisk:  VDiskConfig{Enabled: true, MinSize: "1GB"},
		Output: OutputConfig{Format: "text", Progress: true, Color: "auto", JSONIndent: true, TimeFormat: "iso8601"},
	}
}
