package agent

import (
	"context"
	"errors"
)

// ErrNoPromptAvailable is returned when no prompt source (native or CLI) is available.
var ErrNoPromptAvailable = errors.New("no prompt source available")

// RequestSummary describes a connection request for user approval.
type RequestSummary struct {
	ID          string
	ConnectorID string
}

// DecisionSource decides whether a connection request should be approved.
type DecisionSource interface {
	Confirm(ctx context.Context, req RequestSummary) (bool, error)
}

// Prompter tries a native desktop prompt first, falling back to a CLI prompt.
type Prompter struct {
	native DecisionSource
	cli    DecisionSource
}

// NewPrompter creates a Prompter that tries native first, then cli.
func NewPrompter(native DecisionSource, cli DecisionSource) Prompter {
	return Prompter{
		native: native,
		cli:    cli,
	}
}

// Confirm asks the user to approve the request, trying native UI then CLI.
func (p Prompter) Confirm(ctx context.Context, req RequestSummary) (bool, error) {
	if p.native != nil {
		ok, err := p.native.Confirm(ctx, req)
		if err == nil {
			return ok, nil
		}
	}
	if p.cli == nil {
		return false, ErrNoPromptAvailable
	}
	return p.cli.Confirm(ctx, req)
}
