package approval

import "context"

type RequestSummary struct {
	ID          string
	ConnectorID string
}

type DecisionSource interface {
	Confirm(ctx context.Context, req RequestSummary) (bool, error)
}

type Prompter struct {
	native DecisionSource
	cli    DecisionSource
}

func NewPrompter(native DecisionSource, cli DecisionSource) Prompter {
	return Prompter{
		native: native,
		cli:    cli,
	}
}

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
