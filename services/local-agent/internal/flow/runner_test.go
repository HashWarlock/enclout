package flow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	bundle             api.Bundle
	bundleErr          error
}

func (f *fakeAPI) PostLocalDecision(_ context.Context, _ string, _ bool) error {
	f.localDecisionCalls++
	return nil
}

func (f *fakeAPI) GetAttestationBundle(_ context.Context, _ string) (api.Bundle, error) {
	f.bundleCalls++
	if f.bundleErr != nil {
		return api.Bundle{}, f.bundleErr
	}
	return f.bundle, nil
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
	calls    int
}

func (f *fakeVerifier) Verify(_ context.Context, _ verify.Bundle) (verify.Decision, error) {
	f.calls++
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
	bundle, publicKeyB64 := signedBundleFixture(t, false)
	apiClient := &fakeAPI{bundle: bundle}
	keys := &fakeKeys{}
	quoteVerifier := &fakeVerifier{decision: verify.Decision{Trusted: true}}
	r := NewRunner(apiClient, fakePrompter{approved: true}, quoteVerifier, keys, map[string]string{"v1": publicKeyB64})

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
	if quoteVerifier.calls != 1 {
		t.Fatalf("expected quote verifier to run exactly once")
	}
	if !keys.installed {
		t.Fatalf("expected ssh key installation")
	}
	if apiClient.resultStatus != "connected" {
		t.Fatalf("expected connected result, got %q", apiClient.resultStatus)
	}
}

func TestRunnerVerificationFailure(t *testing.T) {
	bundle, publicKeyB64 := signedBundleFixture(t, false)
	apiClient := &fakeAPI{bundle: bundle}
	keys := &fakeKeys{}
	verr := verify.VerificationError{Code: verify.ReasonReportDataMismatch, Err: errors.New("mismatch")}
	quoteVerifier := &fakeVerifier{err: verr}
	r := NewRunner(apiClient, fakePrompter{approved: true}, quoteVerifier, keys, map[string]string{"v1": publicKeyB64})

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

func TestRunnerRejectsInvalidBundleSignatureBeforeQuoteChecks(t *testing.T) {
	bundle, publicKeyB64 := signedBundleFixture(t, true)
	apiClient := &fakeAPI{bundle: bundle}
	keys := &fakeKeys{}
	quoteVerifier := &fakeVerifier{decision: verify.Decision{Trusted: true}}
	r := NewRunner(apiClient, fakePrompter{approved: true}, quoteVerifier, keys, map[string]string{"v1": publicKeyB64})

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected invalid signature error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status")
	}
	if apiClient.resultReason != verify.ReasonBundleInvalid {
		t.Fatalf("expected %q, got %q", verify.ReasonBundleInvalid, apiClient.resultReason)
	}
	if quoteVerifier.calls != 0 {
		t.Fatalf("expected quote verifier not to run on invalid bundle signature")
	}
	if keys.installed {
		t.Fatalf("expected no key installation on invalid bundle signature")
	}
}

func TestRunnerRejectsUnknownKIDBeforeQuoteChecks(t *testing.T) {
	bundle, _ := signedBundleFixture(t, false)
	bundle.KID = "v2"
	apiClient := &fakeAPI{bundle: bundle}
	keys := &fakeKeys{}
	quoteVerifier := &fakeVerifier{decision: verify.Decision{Trusted: true}}
	r := NewRunner(apiClient, fakePrompter{approved: true}, quoteVerifier, keys, map[string]string{
		"v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected unknown kid error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status")
	}
	if apiClient.resultReason != verify.ReasonBundleInvalid {
		t.Fatalf("expected %q, got %q", verify.ReasonBundleInvalid, apiClient.resultReason)
	}
	if quoteVerifier.calls != 0 {
		t.Fatalf("expected quote verifier not to run on unknown kid")
	}
}

func signedBundleFixture(t *testing.T, tamperSignature bool) (api.Bundle, string) {
	t.Helper()

	payloadRaw := []byte(`{"connector_id":"conn_1","ssh_public_key":"ssh-ed25519 AAAATEST connector@tee","quote_hex":"abcd","mrtd":"mrtd","rtmr0":"rtmr0","rtmr1":"rtmr1","rtmr2":"rtmr2","rtmr3":"rtmr3","report_data_expected_sha256":"abc","policy_version":"v1"}`)
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("failed to unmarshal fixture payload: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}
	signature := ed25519.Sign(privateKey, payloadRaw)
	if tamperSignature {
		signature[0] ^= 0xFF
	}

	return api.Bundle{
			Payload:    payload,
			PayloadRaw: payloadRaw,
			Signature:  base64.StdEncoding.EncodeToString(signature),
			Alg:        "ed25519",
			KID:        "v1",
		},
		base64.StdEncoding.EncodeToString(publicKey)
}
