package install

import (
	"context"
	"errors"
	"testing"

	"enclout/services/local-agent/internal/api"
)

type fakeInstallAPI struct {
	redeemSession        api.InstallSession
	redeemErr            error
	postResultCalls      int
	lastPostResultID     string
	lastPostResultStatus string
	lastPostResultReason string
	postResultErr        error
}

func (f *fakeInstallAPI) RedeemInstallToken(_ context.Context, _ string) (api.InstallSession, error) {
	if f.redeemErr != nil {
		return api.InstallSession{}, f.redeemErr
	}
	return f.redeemSession, nil
}

func (f *fakeInstallAPI) PostInstallResult(_ context.Context, sessionID string, status string, reasonCode string) error {
	f.postResultCalls++
	f.lastPostResultID = sessionID
	f.lastPostResultStatus = status
	f.lastPostResultReason = reasonCode
	return f.postResultErr
}

type fakeServiceInstaller struct {
	lastCfg ServiceConfig
	err     error
	calls   int
}

func (f *fakeServiceInstaller) InstallAndStart(_ context.Context, cfg ServiceConfig) error {
	f.calls++
	f.lastCfg = cfg
	return f.err
}

func TestRunInstallsServiceAndReportsInstalled(t *testing.T) {
	client := &fakeInstallAPI{
		redeemSession: api.InstallSession{
			ID:             "ins_1",
			OpenClawUserID: "usr_1",
			DeviceID:       "dev_1",
			ConnectorID:    "conn_1",
			Status:         "approved",
		},
	}
	installer := &fakeServiceInstaller{}

	err := Run(context.Background(), client, installer, Config{
		InstallToken: "tok_1",
		Label:        "ai.enclout.agent",
		AgentBinary:  "/usr/local/bin/enclout-agent",
		PlistPath:    "/tmp/ai.enclout.agent.plist",
		Env: map[string]string{
			"CONTROL_PLANE_URL": "http://127.0.0.1:8080",
			"LOCAL_USERNAME":    "alice",
			"DCAP_VERIFIER_URL": "http://127.0.0.1:9000",
		},
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if installer.calls != 1 {
		t.Fatalf("expected one install call, got %d", installer.calls)
	}
	if installer.lastCfg.Env["DEVICE_ID"] != "dev_1" {
		t.Fatalf("expected DEVICE_ID from redeemed session, got %q", installer.lastCfg.Env["DEVICE_ID"])
	}
	if client.postResultCalls != 1 {
		t.Fatalf("expected one install result post, got %d", client.postResultCalls)
	}
	if client.lastPostResultStatus != "installed" {
		t.Fatalf("expected installed result status, got %q", client.lastPostResultStatus)
	}
}

func TestRunReportsFailedOnInstallerError(t *testing.T) {
	client := &fakeInstallAPI{
		redeemSession: api.InstallSession{
			ID:       "ins_1",
			DeviceID: "dev_1",
			Status:   "approved",
		},
	}
	installer := &fakeServiceInstaller{err: errors.New("launchctl bootstrap failed")}

	err := Run(context.Background(), client, installer, Config{
		InstallToken: "tok_1",
		Label:        "ai.enclout.agent",
		AgentBinary:  "/usr/local/bin/enclout-agent",
		PlistPath:    "/tmp/ai.enclout.agent.plist",
		Env: map[string]string{
			"CONTROL_PLANE_URL": "http://127.0.0.1:8080",
			"LOCAL_USERNAME":    "alice",
			"DCAP_VERIFIER_URL": "http://127.0.0.1:9000",
		},
	})
	if err == nil {
		t.Fatalf("expected run error")
	}
	if client.postResultCalls != 1 {
		t.Fatalf("expected one failure result post, got %d", client.postResultCalls)
	}
	if client.lastPostResultStatus != "failed" {
		t.Fatalf("expected failed result status, got %q", client.lastPostResultStatus)
	}
	if client.lastPostResultReason != "LaunchdInstallError" {
		t.Fatalf("expected LaunchdInstallError reason, got %q", client.lastPostResultReason)
	}
}

func TestRunReportsFailedOnInvalidConfig(t *testing.T) {
	client := &fakeInstallAPI{
		redeemSession: api.InstallSession{
			ID:       "ins_1",
			DeviceID: "dev_1",
			Status:   "approved",
		},
	}
	installer := &fakeServiceInstaller{}

	err := Run(context.Background(), client, installer, Config{
		InstallToken: "tok_1",
		Label:        "ai.enclout.agent",
		AgentBinary:  "/usr/local/bin/enclout-agent",
		PlistPath:    "/tmp/ai.enclout.agent.plist",
		Env: map[string]string{
			"CONTROL_PLANE_URL": "http://127.0.0.1:8080",
			// Missing LOCAL_USERNAME and DCAP_VERIFIER_URL.
		},
	})
	if err == nil {
		t.Fatalf("expected invalid config error")
	}
	if installer.calls != 0 {
		t.Fatalf("expected no install call on invalid config")
	}
	if client.postResultCalls != 1 {
		t.Fatalf("expected one failure result post, got %d", client.postResultCalls)
	}
	if client.lastPostResultReason != "InvalidConfig" {
		t.Fatalf("expected InvalidConfig reason, got %q", client.lastPostResultReason)
	}
}
