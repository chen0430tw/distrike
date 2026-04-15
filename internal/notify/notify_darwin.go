//go:build darwin

package notify

import "os/exec"

// SendWithPath displays a notification (openPath unused on macOS).
func SendWithPath(title, message, openPath string) error {
	return Send(title, message)
}

// Send displays a macOS notification via osascript.
func Send(title, message string) error {
	script := `display notification "` + escapeAS(message) + `" with title "` + escapeAS(title) + `"`
	cmd := exec.Command("osascript", "-e", script)
	return cmd.Start()
}

// escapeAS escapes double quotes for AppleScript.
func escapeAS(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			result = append(result, '\\', '"')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}
