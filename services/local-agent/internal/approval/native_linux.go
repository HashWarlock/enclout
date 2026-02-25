//go:build linux

package approval

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

type NativePrompter struct{}

func NewNativePrompter() NativePrompter {
	return NativePrompter{}
}

func (NativePrompter) Confirm(ctx context.Context, req RequestSummary) (bool, error) {
	msg := fmt.Sprintf("Approve request %s for connector %s?", req.ID, req.ConnectorID)

	cmd := exec.CommandContext(ctx, "zenity", "--question", "--text", msg, "--title", "Connector Access Request")
	err := cmd.Run()
	if err == nil {
		return true, nil
	}

	// zenity returns non-zero for user deny and for command failure. Detect missing binary.
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return false, err
	}
	return false, nil
}
