package flow

import (
	"context"
	"errors"
	"testing"

	"enclout/services/local-agent/internal/api"
	"enclout/services/local-agent/internal/approval"
	"enclout/services/local-agent/internal/verify"
)

type fakeAPI struct {
	localDecisionCalls int
	bundleCalls        int
	resultStatus       string
	resultReason       string
}

func (f *fakeAPI) PostLocalDecision(_ context.Context, _ string, _ bool) error {
	f.localDecisionCalls++
	return nil
}

func (f *fakeAPI) GetAttestationBundle(_ context.Context, _ string) (api.Bundle, error) {
	f.bundleCalls++
	return api.Bundle{
		Payload: map[string]any{
			"connector_id":               "conn_1",
			"ssh_public_key":             "ssh-ed25519 AAAATEST connector@tee",
			"quote_hex":                  "abcd",
			"mrtd":                       "mrtd",
			"rtmr0":                      "rtmr0",
			"rtmr1":                      "rtmr1",
			"rtmr2":                      "rtmr2",
			"rtmr3":                      "rtmr3",
			"report_data_expected_sha256": "abc",
			"policy_version":             "v1",
		},
		Signature: "sig",
		Alg:       "ed25519",
	}, nil
}

func (f *fakeAPI) PostResult(_ context.Context, _ string, status string, reasonCode string) error {
	f.resultStatus = status
	f.resultReason = reasonCode
	return nil
}

type fakePrompter struct {
	approved bool
	err      error
}

func (f fakePrompter) Confirm(_ context.Context, _ approval.RequestSummary) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.approved, nil
}

type fakeVerifier struct {
	decision verify.Decision
	err      error
}

func (f fakeVerifier) Verify(_ context.Context, _ verify.Bundle) (verify.Decision, error) {
	if f.err != nil {
		return verify.Decision{}, f.err
	}
	return f.decision, nil
}

type fakeKeys struct {
	installed bool
}

func (k *fakeKeys) Install(_ string, _ string) error {
	k.installed = true
	return nil
}

func TestRunnerHappyPath(t *testing.T) {
	apiClient := &fakeAPI{}
	keys := &fakeKeys{}
	r := NewRunner(apiClient, fakePrompter{approved: true}, fakeVerifier{decision: verify.Decision{Trusted: true}}, keys)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiClient.localDecisionCalls != 1 {
		t.Fatalf("expected 1 local decision call")
	}
	if apiClient.bundleCalls != 1 {
		t.Fatalf("expected 1 bundle fetch call")
	}
	if !keys.installed {
		t.Fatalf("expected ssh key installation")
	}
	if apiClient.resultStatus != "connected" {
		t.Fatalf("expected connected result, got %q", apiClient.resultStatus)
	}
}

func TestRunnerVerificationFailure(t *testing.T) {
	apiClient := &fakeAPI{}
	keys := &fakeKeys{}
	verr := verify.VerificationError{Code: verify.ReasonReportDataMismatch, Err: errors.New("mismatch")}
	r := NewRunner(apiClient, fakePrompter{approved: true}, fakeVerifier{err: verr}, keys)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status")
	}
	if apiClient.resultReason != verify.ReasonReportDataMismatch {
		t.Fatalf("unexpected reason %q", apiClient.resultReason)
	}
}
