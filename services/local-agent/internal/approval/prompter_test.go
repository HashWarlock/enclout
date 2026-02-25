package approval

import (
	"context"
	"errors"
	"testing"
)

type fakeSource struct {
	decision bool
	err      error
}

func (f fakeSource) Confirm(_ context.Context, _ RequestSummary) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.decision, nil
}

func TestPromptFallsBackToCLI(t *testing.T) {
	p := NewPrompter(fakeSource{err: errors.New("native unavailable")}, fakeSource{decision: true})
	ok, err := p.Confirm(context.Background(), RequestSummary{ID: "req_1", ConnectorID: "conn_1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected fallback approval to return true")
	}
}
