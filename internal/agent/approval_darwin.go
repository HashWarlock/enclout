//go:build darwin

package agent

import (
	"context"
	"fmt"
	"os/exec"
)

// NativePrompter uses macOS osascript to show a native dialog.
type NativePrompter struct{}

// NewNativePrompter creates a NativePrompter for macOS.
func NewNativePrompter() NativePrompter {
	return NativePrompter{}
}

// Confirm shows an osascript dialog and returns true if the user clicks Approve.
func (NativePrompter) Confirm(ctx context.Context, req RequestSummary) (bool, error) {
	title := "Connector Access Request"
	msg := fmt.Sprintf("Approve request %s for connector %s?", req.ID, req.ConnectorID)
	script := fmt.Sprintf(`display dialog "%s" with title "%s" buttons {"Deny", "Approve"} default button "Deny"`, msg, title)

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	return string(out) != "", nil
}
