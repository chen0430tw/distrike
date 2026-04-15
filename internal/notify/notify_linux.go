//go:build linux

package notify

import "os/exec"

// Send displays a Linux desktop notification via notify-send.
func Send(title, message string) error {
	cmd := exec.Command("notify-send", "-a", "Distrike", "-u", "critical", title, message)
	return cmd.Start()
}
