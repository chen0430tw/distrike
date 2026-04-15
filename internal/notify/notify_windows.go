//go:build windows

package notify

import (
	"fmt"
	"os/exec"
)

// Send displays a Windows balloon tip notification via PowerShell.
// If openPath is provided, clicking the notification opens that path in Explorer.
func Send(title, message string) error {
	return SendWithPath(title, message, "")
}

// SendWithPath displays a notification. Clicking it opens the given path in Explorer.
func SendWithPath(title, message, openPath string) error {
	onClick := ""
	if openPath != "" {
		onClick = fmt.Sprintf(`
$n.Add_BalloonTipClicked({
    Start-Process explorer.exe -ArgumentList '%s'
})`, escapePS(openPath))
	}

	ps := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Warning
$n.Visible = $true
$n.BalloonTipTitle = '%s'
$n.BalloonTipText = '%s'%s
$n.ShowBalloonTip(30000)
Start-Sleep -Seconds 10
$n.Dispose()
`, escapePS(title), escapePS(message), onClick)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	return cmd.Start()
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
