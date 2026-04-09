package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"enclout/internal/agent"
	"enclout/internal/attestation"
	"enclout/internal/config"
)

type fakeAgentRequestClient struct {
	bundle        agent.SignedBundle
	resultStatus  string
	resultReason  string
	decisionCalls int
	bundleCalls   int
	requestStatus string
}

func (f *fakeAgentRequestClient) PostDecision(_ context.Context, _ string, _ bool) error {
	f.decisionCalls++
	return nil
}

func (f *fakeAgentRequestClient) GetBundle(_ context.Context, _ string) (agent.SignedBundle, error) {
	f.bundleCalls++
	return f.bundle, nil
}

func (f *fakeAgentRequestClient) PostResult(_ context.Context, _ string, status string, reasonCode string) error {
	f.resultStatus = status
	f.resultReason = reasonCode
	return nil
}

func (f *fakeAgentRequestClient) GetRequestStatus(_ context.Context, _ string) (string, error) {
	if f.requestStatus == "" {
		return "approved", nil
	}
	return f.requestStatus, nil
}

type fakeDecisionSource struct {
	approved bool
}

func (f fakeDecisionSource) Confirm(_ context.Context, _ agent.RequestSummary) (bool, error) {
	return f.approved, nil
}

type fakeBundleVerifier struct {
	decision attestation.Decision
}

func (f *fakeBundleVerifier) Verify(_ context.Context, _ attestation.Bundle) (attestation.Decision, error) {
	return f.decision, nil
}

type fakeKeyInstaller struct {
	installed bool
}

func (k *fakeKeyInstaller) Install(_ string, _ string) error {
	k.installed = true
	return nil
}

func (k *fakeKeyInstaller) InstallForConnector(_ string, _ string, _ string) error {
	k.installed = true
	return nil
}

func (k *fakeKeyInstaller) CleanupStale(_ string, _ string) error {
	return nil
}

type fakeTrustedKeys struct {
	keys map[string]string
}

func (f *fakeTrustedKeys) TrustedKeys(_ context.Context) (map[string]string, error) {
	out := make(map[string]string, len(f.keys))
	for kid, key := range f.keys {
		out[kid] = key
	}
	return out, nil
}

type fakeAuditSink struct {
	calls int
}

func (f *fakeAuditSink) Ready(_ context.Context) error {
	f.calls++
	return nil
}

func TestAgentCmd_RegistersAllowListFlags(t *testing.T) {
	cmd := agentCmd()

	if cmd.Flags().Lookup("allow-mrtd") == nil {
		t.Fatal("expected allow-mrtd flag to be registered")
	}
	if cmd.Flags().Lookup("allow-rtmr3") == nil {
		t.Fatal("expected allow-rtmr3 flag to be registered")
	}
}

func TestLoadAgentConfig_AppliesEnvAndParsesAllowLists(t *testing.T) {
	t.Setenv("ENCLOUT_SERVER", "https://control.example")
	t.Setenv("ENCLOUT_DEVICE_ID", "device-1")
	t.Setenv("ENCLOUT_USERNAME", "deploy")
	t.Setenv("ENCLOUT_DCAP_URL", "https://dcap.example")
	t.Setenv("ENCLOUT_AUDIT_DIR", "/var/tmp/enclout-audit")
	t.Setenv("ENCLOUT_ALLOW_MRTD", " mrtd-a , , mrtd-b ")
	t.Setenv("ENCLOUT_ALLOW_RTMR3", " rtmr3-a,rtmr3-b ")

	cmd := agentCmd()
	bindEnvDefaults(cmd, map[string]string{
		"server":      "ENCLOUT_SERVER",
		"device-id":   "ENCLOUT_DEVICE_ID",
		"username":    "ENCLOUT_USERNAME",
		"audit-dir":   "ENCLOUT_AUDIT_DIR",
		"dcap-url":    "ENCLOUT_DCAP_URL",
		"allow-mrtd":  "ENCLOUT_ALLOW_MRTD",
		"allow-rtmr3": "ENCLOUT_ALLOW_RTMR3",
		"log-format":  "ENCLOUT_LOG_FORMAT",
	})

	var cfg config.AgentConfig
	if err := loadAgentConfig(cmd, &cfg); err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Server != "https://control.example" {
		t.Fatalf("expected server from env, got %q", cfg.Server)
	}
	if cfg.DeviceID != "device-1" {
		t.Fatalf("expected device ID from env, got %q", cfg.DeviceID)
	}
	if cfg.Username != "deploy" {
		t.Fatalf("expected username from env, got %q", cfg.Username)
	}
	if cfg.DCAPUrl != "https://dcap.example" {
		t.Fatalf("expected DCAP URL from env, got %q", cfg.DCAPUrl)
	}
	if cfg.AuditDir != "/var/tmp/enclout-audit" {
		t.Fatalf("expected audit dir from env, got %q", cfg.AuditDir)
	}

	wantMRTD := []string{"mrtd-a", "mrtd-b"}
	if len(cfg.AllowMRTD) != len(wantMRTD) {
		t.Fatalf("expected MRTD allowlist %#v, got %#v", wantMRTD, cfg.AllowMRTD)
	}
	for i := range wantMRTD {
		if cfg.AllowMRTD[i] != wantMRTD[i] {
			t.Fatalf("expected MRTD allowlist %#v, got %#v", wantMRTD, cfg.AllowMRTD)
		}
	}

	wantRTMR3 := []string{"rtmr3-a", "rtmr3-b"}
	if len(cfg.AllowRTMR3) != len(wantRTMR3) {
		t.Fatalf("expected RTMR3 allowlist %#v, got %#v", wantRTMR3, cfg.AllowRTMR3)
	}
	for i := range wantRTMR3 {
		if cfg.AllowRTMR3[i] != wantRTMR3[i] {
			t.Fatalf("expected RTMR3 allowlist %#v, got %#v", wantRTMR3, cfg.AllowRTMR3)
		}
	}
}

func TestNewAgentRunner_WiresAuditSink(t *testing.T) {
	bundle, publicKeyB64 := testSignedBundle(t, false)
	client := &fakeAgentRequestClient{bundle: bundle, requestStatus: "approved"}
	verifier := &fakeBundleVerifier{decision: attestation.Decision{Trusted: true}}
	keys := &fakeKeyInstaller{}
	signingKeys := &fakeTrustedKeys{keys: map[string]string{"v1": publicKeyB64}}
	auditSink := &fakeAuditSink{}

	runner := newAgentRunner(client, fakeDecisionSource{approved: true}, verifier, keys, signingKeys, "alice", nil, auditSink)

	err := runner.Process(context.Background(), agent.Request{
		ID:          "req_1",
		ConnectorID: "conn_1",
		LocalUser:   "ignored",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected audit sink readiness check once, got %d", auditSink.calls)
	}
	if client.resultStatus != "connected" {
		t.Fatalf("expected connected status, got %q", client.resultStatus)
	}
	if !keys.installed {
		t.Fatal("expected ssh key installation")
	}
}

func TestFilesystemAuditSink_Ready(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	sink := filesystemAuditSink{dir: dir}

	if err := sink.Ready(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected audit dir to exist: %v", err)
	}
}

func TestExpandHomeDir_ExpandsLeadingTilde(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv("HOME", home)

	got := expandHomeDir("~/audit")
	want := filepath.Join(home, "audit")
	if got != want {
		t.Fatalf("expected expanded path %q, got %q", want, got)
	}
}

func testSignedBundle(t *testing.T, tamperSignature bool) (agent.SignedBundle, string) {
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

	return agent.SignedBundle{
			Payload:    payload,
			PayloadRaw: payloadRaw,
			Signature:  base64.StdEncoding.EncodeToString(signature),
			Alg:        "ed25519",
			KID:        "v1",
		},
		base64.StdEncoding.EncodeToString(publicKey)
}
