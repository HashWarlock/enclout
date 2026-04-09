package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"enclout/internal/attestation"
)

type fakeRequestClient struct {
	decisionCalls int
	bundleCalls   int
	statusCalls   int
	resultStatus  string
	resultReason  string
	bundle        SignedBundle
	bundleErr     error
	requestStatus string
}

func (f *fakeRequestClient) PostDecision(_ context.Context, _ string, _ bool) error {
	f.decisionCalls++
	return nil
}

func (f *fakeRequestClient) GetBundle(_ context.Context, _ string) (SignedBundle, error) {
	f.bundleCalls++
	if f.bundleErr != nil {
		return SignedBundle{}, f.bundleErr
	}
	return f.bundle, nil
}

func (f *fakeRequestClient) PostResult(_ context.Context, _ string, status string, reasonCode string) error {
	f.resultStatus = status
	f.resultReason = reasonCode
	return nil
}

func (f *fakeRequestClient) GetRequestStatus(_ context.Context, _ string) (string, error) {
	f.statusCalls++
	if f.requestStatus == "" {
		return "approved", nil
	}
	return f.requestStatus, nil
}

type fakeDecisionSource struct {
	approved bool
	err      error
}

func (f fakeDecisionSource) Confirm(_ context.Context, _ RequestSummary) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.approved, nil
}

type fakeBundleVerifier struct {
	decision attestation.Decision
	err      error
	calls    int
}

func (f *fakeBundleVerifier) Verify(_ context.Context, _ attestation.Bundle) (attestation.Decision, error) {
	f.calls++
	if f.err != nil {
		return attestation.Decision{}, f.err
	}
	return f.decision, nil
}

type fakeKeyInstaller struct {
	installed        bool
	usedManagedFlow  bool
	cleanupCalled    bool
	lastConnectorID  string
	lastManagedUser  string
	lastInstallUser  string
	lastInstalledKey string
}

func (k *fakeKeyInstaller) Install(_ string, _ string) error {
	k.installed = true
	return nil
}

func (k *fakeKeyInstaller) InstallForConnector(username, connectorID, pubKey string) error {
	k.installed = true
	k.usedManagedFlow = true
	k.lastManagedUser = username
	k.lastConnectorID = connectorID
	k.lastInstalledKey = pubKey
	return nil
}

func (k *fakeKeyInstaller) CleanupStale(username, activeConnectorID string) error {
	k.cleanupCalled = true
	k.lastInstallUser = username
	k.lastConnectorID = activeConnectorID
	return nil
}

type fakeTrustedKeys struct {
	keys  map[string]string
	err   error
	calls int
}

func (f *fakeTrustedKeys) TrustedKeys(_ context.Context) (map[string]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]string, len(f.keys))
	for kid, key := range f.keys {
		out[kid] = key
	}
	return out, nil
}

type fakeAuditSink struct {
	err   error
	calls int
}

func (f *fakeAuditSink) Ready(_ context.Context) error {
	f.calls++
	return f.err
}

func TestRunner_Process_FullFlow(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	apiClient := &fakeRequestClient{bundle: bundle, requestStatus: "approved"}
	keys := &fakeKeyInstaller{}
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	auditSink := &fakeAuditSink{}
	r := NewRunnerWithAuditSink(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, auditSink, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiClient.decisionCalls != 1 {
		t.Fatalf("expected 1 decision call, got %d", apiClient.decisionCalls)
	}
	if apiClient.bundleCalls != 1 {
		t.Fatalf("expected 1 bundle fetch call, got %d", apiClient.bundleCalls)
	}
	if verifier.calls != 1 {
		t.Fatalf("expected verifier to run once, got %d", verifier.calls)
	}
	if signingKeys.calls != 1 {
		t.Fatalf("expected trusted keyset lookup to run once, got %d", signingKeys.calls)
	}
	if !keys.installed {
		t.Fatalf("expected ssh key installation")
	}
	if !keys.usedManagedFlow {
		t.Fatalf("expected managed key install flow")
	}
	if !keys.cleanupCalled {
		t.Fatalf("expected stale key cleanup")
	}
	if apiClient.resultStatus != "connected" {
		t.Fatalf("expected connected result, got %q", apiClient.resultStatus)
	}
	if apiClient.statusCalls != 2 {
		t.Fatalf("expected request status check twice, got %d", apiClient.statusCalls)
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected audit sink readiness check once, got %d", auditSink.calls)
	}
}

func TestRunner_Process_UserDenied(t *testing.T) {
	apiClient := &fakeRequestClient{}
	r := NewRunner(apiClient, fakeDecisionSource{approved: false}, nil, nil, nil, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if !errors.Is(err, ErrUserDenied) {
		t.Fatalf("expected ErrUserDenied, got %v", err)
	}
	if apiClient.decisionCalls != 1 {
		t.Fatalf("expected 1 decision call, got %d", apiClient.decisionCalls)
	}
}

func TestRunner_Process_VerificationFailed(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	apiClient := &fakeRequestClient{bundle: bundle}
	keys := &fakeKeyInstaller{}
	verr := attestation.VerificationError{Code: attestation.ReasonReportDataMismatch, Err: errors.New("mismatch")}
	verifier := &fakeBundleVerifier{err: verr}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	r := NewRunner(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status, got %q", apiClient.resultStatus)
	}
	if apiClient.resultReason != attestation.ReasonReportDataMismatch {
		t.Fatalf("unexpected reason %q", apiClient.resultReason)
	}
}

func TestRunner_Process_InvalidSignature(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, true)
	apiClient := &fakeRequestClient{bundle: bundle}
	keys := &fakeKeyInstaller{}
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	r := NewRunner(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected invalid signature error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status, got %q", apiClient.resultStatus)
	}
	if apiClient.resultReason != attestation.ReasonBundleInvalid {
		t.Fatalf("expected %q, got %q", attestation.ReasonBundleInvalid, apiClient.resultReason)
	}
	if verifier.calls != 0 {
		t.Fatalf("expected verifier not to run on invalid bundle signature")
	}
	if keys.installed {
		t.Fatalf("expected no key installation on invalid bundle signature")
	}
}

func TestRunner_Process_UsesConfiguredUsername(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	apiClient := &fakeRequestClient{bundle: bundle, requestStatus: "approved"}
	keysDir := t.TempDir()
	keys := NewSSHKeyManager(keysDir)
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	auditSink := &fakeAuditSink{}
	r := NewRunnerWithUsernameAndAuditSink(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, "alice", auditSink, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "device-123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantPath := filepath.Join(keysDir, "alice", "authorized_keys")
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("expected authorized_keys at %q: %v", wantPath, err)
	}
	if string(got) != "ssh-ed25519 AAAATEST connector@tee\n" {
		t.Fatalf("unexpected authorized_keys contents: %q", string(got))
	}

	unexpectedPath := filepath.Join(keysDir, "device-123", "authorized_keys")
	if _, err := os.Stat(unexpectedPath); !os.IsNotExist(err) {
		t.Fatalf("expected no authorized_keys at device-id path %q, got err=%v", unexpectedPath, err)
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected audit sink readiness check once, got %d", auditSink.calls)
	}
}

func TestRunner_Process_AuditSinkUnhealthy(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	apiClient := &fakeRequestClient{bundle: bundle, requestStatus: "approved"}
	keys := &fakeKeyInstaller{}
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	auditSink := &fakeAuditSink{err: errors.New("audit sink unavailable")}
	r := NewRunnerWithAuditSink(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, auditSink, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if apiClient.resultStatus != "verification_failed" {
		t.Fatalf("expected verification_failed status, got %q", apiClient.resultStatus)
	}
	if apiClient.resultReason != auditSinkNotReadyReason {
		t.Fatalf("expected audit sink failure reason, got %q", apiClient.resultReason)
	}
	if !errors.Is(err, auditSink.err) {
		t.Fatalf("expected audit sink error, got %v", err)
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected audit sink readiness check once, got %d", auditSink.calls)
	}
	if keys.installed {
		t.Fatalf("expected ssh key installation not to run when audit gate is unhealthy")
	}
	if apiClient.resultStatus == "connected" {
		t.Fatalf("expected not to report connected")
	}
}

func TestRunner_Process_StopsWhenRequestRevokedBeforeInstall(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	apiClient := &fakeRequestClient{bundle: bundle, requestStatus: "revoked"}
	keys := &fakeKeyInstaller{}
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	auditSink := &fakeAuditSink{}
	r := NewRunnerWithAuditSink(apiClient, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, auditSink, nil)

	err := r.Process(context.Background(), Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "alice",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if keys.installed {
		t.Fatalf("expected key install to be skipped for revoked request")
	}
	if apiClient.resultStatus != "" {
		t.Fatalf("expected no result post for revoked request, got %q", apiClient.resultStatus)
	}
	if apiClient.statusCalls != 1 {
		t.Fatalf("expected request status check once, got %d", apiClient.statusCalls)
	}
}

func testSignedBundle(t *testing.T, tamperSignature bool) (SignedBundle, string) {
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

	return SignedBundle{
			Payload:    payload,
			PayloadRaw: payloadRaw,
			Signature:  base64.StdEncoding.EncodeToString(signature),
			Alg:        "ed25519",
			KID:        "v1",
		},
		base64.StdEncoding.EncodeToString(publicKey)
}
