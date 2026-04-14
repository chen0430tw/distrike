package hunter

import "time"

// PreyKind classifies the type of cleanable item.
type PreyKind string

const (
	KindCache    PreyKind = "cache"
	KindTemp     PreyKind = "temp"
	KindVDisk    PreyKind = "vdisk"
	KindBackup   PreyKind = "backup"
	KindDownload PreyKind = "download"
	KindOrphan   PreyKind = "orphan"
	KindLog      PreyKind = "log"
)

// Risk indicates how safe it is to clean this prey.
type Risk string

const (
	RiskSafe    Risk = "safe"    // Auto-cleanable
	RiskCaution Risk = "caution" // Needs confirmation
	RiskDanger  Risk = "danger"  // Manual only
)

// Action describes how to clean a prey item.
type Action struct {
	Type    string `json:"type"`              // "command" or "manual"
	Command string `json:"command,omitempty"` // Shell command to execute
	Shell   string `json:"shell,omitempty"`   // "default", "powershell", "bash"
	Hint    string `json:"hint,omitempty"`    // Human-readable hint for manual actions
}

// Prey represents an identified cleanable item.
type Prey struct {
	Path        string    `json:"path"`
	SizeBytes   int64     `json:"size_bytes"`
	Kind        PreyKind  `json:"kind"`
	Risk        Risk      `json:"risk"`
	Platform    string    `json:"platform"` // "windows", "darwin", "linux", "all"
	Description string    `json:"description"`
	Action      Action    `json:"action"`
	LastAccess  time.Time `json:"last_access,omitempty"`
}
