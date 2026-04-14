package hunter

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// DockerDetector identifies cleanable Docker resources.
type DockerDetector struct {
	executable string
}

// DockerStatus holds Docker disk usage information.
type DockerStatus struct {
	Available         bool  `json:"available"`
	DanglingImages    int   `json:"dangling_images"`
	StoppedContainers int   `json:"stopped_containers"`
	UnusedVolumes     int   `json:"unused_volumes"`
	BuildCacheBytes   int64 `json:"build_cache_bytes"`
	ReclaimableBytes  int64 `json:"reclaimable_bytes"`
}

// dockerDFEntry represents one row from `docker system df --format json`.
type dockerDFEntry struct {
	Type        string `json:"Type"`
	TotalCount  int    `json:"TotalCount"`
	Active      int    `json:"Active"`
	Size        string `json:"Size"`
	Reclaimable string `json:"Reclaimable"`
}

// dockerContainer represents a container from `docker ps -a --format json`.
type dockerContainer struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	Status string `json:"Status"`
	Size   string `json:"Size"`
	State  string `json:"State"`
}

// Detect checks Docker status and returns cleanable items as prey.
func (d *DockerDetector) Detect() ([]Prey, *DockerStatus, error) {
	dockerPath := d.findDocker()
	if dockerPath == "" {
		return nil, &DockerStatus{Available: false}, nil
	}
	d.executable = dockerPath

	// Check if Docker daemon is running.
	if err := exec.Command(dockerPath, "info").Run(); err != nil {
		return nil, &DockerStatus{Available: false}, nil
	}

	status := &DockerStatus{Available: true}
	var preys []Prey

	// Get disk usage via docker system df.
	dfPreys, err := d.parseDiskUsage(status)
	if err == nil {
		preys = append(preys, dfPreys...)
	}

	// Get stopped containers.
	containerPreys, err := d.parseStoppedContainers(status)
	if err == nil {
		preys = append(preys, containerPreys...)
	}

	return preys, status, nil
}

// findDocker locates the docker executable.
func (d *DockerDetector) findDocker() string {
	if d.executable != "" {
		return d.executable
	}

	// Try PATH first.
	if path, err := exec.LookPath("docker"); err == nil {
		return path
	}

	// Try common locations.
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{
			`C:\Program Files\Docker\Docker\resources\bin\docker.exe`,
			`C:\ProgramData\DockerDesktop\version-bin\docker.exe`,
		}
	case "darwin":
		candidates = []string{
			"/usr/local/bin/docker",
			"/opt/homebrew/bin/docker",
		}
	default: // linux
		candidates = []string{
			"/usr/bin/docker",
			"/usr/local/bin/docker",
			"/snap/bin/docker",
		}
	}

	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}

	return ""
}

// parseDiskUsage runs docker system df and parses the output.
func (d *DockerDetector) parseDiskUsage(status *DockerStatus) ([]Prey, error) {
	out, err := exec.Command(d.executable, "system", "df", "--format", "{{json .}}").Output()
	if err != nil {
		return nil, fmt.Errorf("docker system df: %w", err)
	}

	var preys []Prey
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry dockerDFEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		reclaimable := parseSizeString(entry.Reclaimable)
		status.ReclaimableBytes += reclaimable

		switch entry.Type {
		case "Images":
			inactive := entry.TotalCount - entry.Active
			if inactive > 0 {
				status.DanglingImages = inactive
				if reclaimable > 0 {
					preys = append(preys, Prey{
						Path:        "docker:images",
						SizeBytes:   reclaimable,
						Kind:        KindCache,
						Risk:        RiskSafe,
						Platform:    "all",
						Description: fmt.Sprintf("Docker dangling/unused images (%d inactive)", inactive),
						Action:      Action{Type: "command", Command: "docker image prune -a"},
					})
				}
			}
		case "Containers":
			// Handled separately by parseStoppedContainers.
		case "Local Volumes":
			inactive := entry.TotalCount - entry.Active
			if inactive > 0 {
				status.UnusedVolumes = inactive
				if reclaimable > 0 {
					preys = append(preys, Prey{
						Path:        "docker:volumes",
						SizeBytes:   reclaimable,
						Kind:        KindOrphan,
						Risk:        RiskCaution,
						Platform:    "all",
						Description: fmt.Sprintf("Docker unused volumes (%d)", inactive),
						Action:      Action{Type: "command", Command: "docker volume prune"},
					})
				}
			}
		case "Build Cache":
			status.BuildCacheBytes = parseSizeString(entry.Size)
			if reclaimable > 0 {
				preys = append(preys, Prey{
					Path:        "docker:buildcache",
					SizeBytes:   reclaimable,
					Kind:        KindCache,
					Risk:        RiskSafe,
					Platform:    "all",
					Description: "Docker build cache",
					Action:      Action{Type: "command", Command: "docker builder prune"},
				})
			}
		}
	}

	return preys, nil
}

// parseStoppedContainers lists exited containers.
func (d *DockerDetector) parseStoppedContainers(status *DockerStatus) ([]Prey, error) {
	out, err := exec.Command(d.executable, "ps", "-a",
		"--filter", "status=exited",
		"--format", "{{json .}}").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}

	var preys []Prey
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var c dockerContainer
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}

		status.StoppedContainers++
		size := parseSizeString(c.Size)
		status.ReclaimableBytes += size

		name := c.Names
		if name == "" {
			name = c.ID
		}

		preys = append(preys, Prey{
			Path:        fmt.Sprintf("docker:container/%s", c.ID),
			SizeBytes:   size,
			Kind:        KindOrphan,
			Risk:        RiskSafe,
			Platform:    "all",
			Description: fmt.Sprintf("Stopped container: %s (%s)", name, c.Image),
			Action:      Action{Type: "command", Command: fmt.Sprintf("docker rm %s", c.ID)},
		})
	}

	return preys, nil
}

// parseSizeString parses Docker's human-readable size strings like "2.5GB", "100MB", "1.2kB".
// Returns approximate bytes. On parse failure, returns 0.
func parseSizeString(s string) int64 {
	// Docker sometimes appends reclaimable percentage like "2.5GB (50%)"
	if idx := strings.Index(s, "("); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}
	s = strings.TrimSpace(s)
	if s == "" || s == "0B" || s == "0" {
		return 0
	}

	// Multipliers for Docker size suffixes.
	multipliers := []struct {
		suffix string
		mult   float64
	}{
		{"TB", 1e12},
		{"GB", 1e9},
		{"MB", 1e6},
		{"kB", 1e3},
		{"B", 1},
	}

	for _, m := range multipliers {
		if strings.HasSuffix(s, m.suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(s, m.suffix))
			var val float64
			if _, err := fmt.Sscanf(numStr, "%f", &val); err == nil {
				return int64(val * m.mult)
			}
		}
	}

	return 0
}
