package verify

import (
	"context"
	"errors"
)

type UnimplementedDCAP struct{}

func (UnimplementedDCAP) Verify(_ context.Context, _ string) (DCAPResult, error) {
	return DCAPResult{}, errors.New("dcap verifier integration required")
}
