package signal

import (
	"fmt"
	"math"
)

// Light represents the four-color capacity signal level.
// Adapted from treesea/CFPAI risk signal system.
type Light string

const (
	Green  Light = "green"  // Normal, ample free space
	Yellow Light = "yellow" // Tightening or concentrated usage
	Red    Light = "red"    // Dangerous, cleanup recommended
	Purple Light = "purple" // Critical / black swan, near exhaustion
)

// Thresholds defines the trigger conditions for each signal level.
type Thresholds struct {
	PurpleUsedRatio         float64 `yaml:"purple_used_ratio"`
	PurpleConcentration     float64 `yaml:"purple_concentration"`
	PurpleRequiresBelowKill bool    `yaml:"purple_requires_below_kill_line"`

	RedUsedRatio     float64 `yaml:"red_used_ratio"`
	RedConcentration float64 `yaml:"red_concentration"`

	YellowUsedRatio     float64 `yaml:"yellow_used_ratio"`
	YellowConcentration float64 `yaml:"yellow_concentration"`
}

// DefaultThresholds returns the CFPAI-derived defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		PurpleUsedRatio:         0.90,
		PurpleConcentration:     0.60,
		PurpleRequiresBelowKill: true,
		RedUsedRatio:            0.85,
		RedConcentration:        0.50,
		YellowUsedRatio:         0.70,
		YellowConcentration:     0.35,
	}
}

// Signal holds the computed capacity signal for a drive.
type Signal struct {
	Light            Light   `json:"light"`
	RiskPct          float64 `json:"risk_pct"`
	UsedPct          float64 `json:"used_pct"`
	ConcentrationPct float64 `json:"concentration_pct"`
	FreeBudgetPct    float64 `json:"free_budget_pct"`
	Description      string  `json:"description"`
	Action           string  `json:"action"`
}

// Classify determines the signal light for a drive.
func Classify(usedRatio, concentration float64, freeBytes, killLine int64, t Thresholds) Signal {
	freeBudget := float64(freeBytes) / float64(killLine)
	riskPct := math.Min(100, usedRatio*60+concentration*40)

	var light Light
	switch {
	// Hard rules: free space alone determines critical/danger signals.
	// These fire regardless of concentration (which may be unavailable).
	case freeBytes < 1<<30: // < 1 GB — always PURPLE
		light = Purple
	case freeBytes < killLine: // < kill-line — always RED
		light = Red
	// Soft rules: combined ratio + concentration for early warning.
	case usedRatio > t.PurpleUsedRatio && concentration > t.PurpleConcentration && freeBudget < 1.0:
		light = Purple
	case usedRatio > t.RedUsedRatio && concentration > t.RedConcentration:
		light = Red
	case usedRatio > t.YellowUsedRatio || concentration > t.YellowConcentration:
		light = Yellow
	default:
		light = Green
	}

	sig := Signal{
		Light:            light,
		RiskPct:          riskPct,
		UsedPct:          usedRatio * 100,
		ConcentrationPct: concentration * 100,
		FreeBudgetPct:    freeBudget * 100,
	}

	// Generate description and action text
	switch light {
	case Green:
		sig.Description = "空间充裕，无需操作"
		sig.Action = "No action needed"
	case Yellow:
		sig.Description = fmt.Sprintf("空间偏紧，集中度 %.0f%% 偏高", concentration*100)
		sig.Action = "Review largest directories for cleanup opportunities"
	case Red:
		sig.Description = "建议立即清理"
		sig.Action = "Run distrike hunt"
	case Purple:
		sig.Description = "极度危险，即将耗尽"
		sig.Action = "Immediate cleanup required"
	}

	return sig
}

// ComputeHHI calculates the Herfindahl-Hirschman Index from directory sizes.
// HHI range: [1/N, 1.0], higher = more concentrated.
func ComputeHHI(sizes []int64, totalUsed int64) float64 {
	if totalUsed <= 0 {
		return 0
	}
	hhi := 0.0
	for _, size := range sizes {
		share := float64(size) / float64(totalUsed)
		hhi += share * share
	}
	return hhi
}
