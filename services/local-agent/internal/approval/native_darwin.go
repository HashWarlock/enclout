//go:build darwin

package approval

import (
	"context"
	"fmt"
	"os/exec"
)

type NativePrompter struct{}

func NewNativePrompter() NativePrompter {
	return NativePrompter{}
}

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
