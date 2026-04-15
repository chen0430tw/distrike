//go:build windows

package notify

import (
	"fmt"
	"os/exec"
)

// Send displays a Windows balloon tip notification via PowerShell.
func Send(title, message string) error {
	// Use PowerShell with System.Windows.Forms NotifyIcon for a non-blocking balloon tip.
	// This works on Windows 10/11 without any extra modules.
	ps := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Warning
$n.Visible = $true
$n.BalloonTipTitle = '%s'
$n.BalloonTipText = '%s'
$n.ShowBalloonTip(10000)
Start-Sleep -Seconds 2
$n.Dispose()
`, escapePS(title), escapePS(message))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	return cmd.Start() // non-blocking: fire and forget
}

// escapePS escapes single quotes for PowerShell string literals.
func escapePS(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			result = append(result, '\'', '\'')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}
