//go:build linux

package notify

import "os/exec"

// SendWithPath displays a notification (openPath unused on Linux).
func SendWithPath(title, message, openPath string) error {
	return Send(title, message)
}

// Send displays a Linux desktop notification via notify-send.
func Send(title, message string) error {
	cmd := exec.Command("notify-send", "-a", "Distrike", "-u", "critical", title, message)
	return cmd.Start()
}
