package requests

import (
	"testing"
	"time"
)

type fakeClock struct {
	current time.Time
}

func (f *fakeClock) Now() time.Time {
	return f.current
}

func TestCreateAndExpireRequest(t *testing.T) {
	start := time.Date(2026, 2, 24, 17, 0, 0, 0, time.UTC)
	clock := &fakeClock{current: start}
	store := NewInMemoryStoreWithClock(clock)

	req, err := store.Create(CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	if req.Status != StatusPendingLocalConfirm {
		t.Fatalf("expected status %q, got %q", StatusPendingLocalConfirm, req.Status)
	}

	clock.current = start.Add(6 * time.Minute)
	got, err := store.Get(req.ID)
	if err != nil {
		t.Fatalf("unexpected get error: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("expected request to expire, got %q", got.Status)
	}
}

func TestSetLocalDecisionApproveTransition(t *testing.T) {
	store := NewInMemoryStoreWithClock(&fakeClock{current: time.Now().UTC()})
	req, err := store.Create(CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "slack",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	updated, err := store.SetLocalDecision(req.ID, true)
	if err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}
	if updated.Status != StatusApproved {
		t.Fatalf("expected approved status, got %q", updated.Status)
	}
}

func TestSetResultVerificationFailedTransition(t *testing.T) {
	store := NewInMemoryStoreWithClock(&fakeClock{current: time.Now().UTC()})
	req, err := store.Create(CreateInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "discord",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	_, err = store.SetLocalDecision(req.ID, true)
	if err != nil {
		t.Fatalf("unexpected decision error: %v", err)
	}

	updated, err := store.SetResult(req.ID, StatusVerificationFailed, "ReportDataMismatch")
	if err != nil {
		t.Fatalf("unexpected set result error: %v", err)
	}
	if updated.Status != StatusVerificationFailed {
		t.Fatalf("expected verification_failed status, got %q", updated.Status)
	}
	if updated.ReasonCode != "ReportDataMismatch" {
		t.Fatalf("expected reason code to be set")
	}
}

func TestCreateInstallSessionApproveRedeemOneTimeAndInstall(t *testing.T) {
	start := time.Date(2026, 2, 24, 18, 0, 0, 0, time.UTC)
	clock := &fakeClock{current: start}
	store := NewInMemoryStoreWithClock(clock)

	session, token, err := store.CreateInstallSession(CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "signal",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create install session error: %v", err)
	}
	if session.Status != InstallStatusRequested {
		t.Fatalf("expected requested status, got %q", session.Status)
	}
	if token == "" {
		t.Fatalf("expected one-time install token")
	}

	_, err = store.RedeemInstallToken(token)
	if err == nil {
		t.Fatalf("expected redeem before approval to fail")
	}
	if err != ErrInvalidTransition {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}

	session, err = store.SetInstallApproval(session.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}
	if session.Status != InstallStatusApproved {
		t.Fatalf("expected approved status, got %q", session.Status)
	}

	redeemed, err := store.RedeemInstallToken(token)
	if err != nil {
		t.Fatalf("unexpected redeem error: %v", err)
	}
	if redeemed.ID != session.ID {
		t.Fatalf("expected redeemed session %q, got %q", session.ID, redeemed.ID)
	}

	_, err = store.RedeemInstallToken(token)
	if err == nil {
		t.Fatalf("expected second redeem to fail")
	}
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for consumed token, got %v", err)
	}

	session, err = store.SetInstallResult(session.ID, InstallStatusInstalled, "")
	if err != nil {
		t.Fatalf("unexpected install result error: %v", err)
	}
	if session.Status != InstallStatusInstalled {
		t.Fatalf("expected installed status, got %q", session.Status)
	}
}

func TestInstallSessionFailedTransition(t *testing.T) {
	store := NewInMemoryStoreWithClock(&fakeClock{current: time.Now().UTC()})

	session, _, err := store.CreateInstallSession(CreateInstallInput{
		OpenClawUserID: "usr_1",
		DeviceID:       "dev_1",
		ConnectorID:    "conn_1",
		SourceChannel:  "telegram",
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected create install session error: %v", err)
	}

	session, err = store.SetInstallApproval(session.ID, true)
	if err != nil {
		t.Fatalf("unexpected approval error: %v", err)
	}

	session, err = store.SetInstallResult(session.ID, InstallStatusFailed, "BootstrapError")
	if err != nil {
		t.Fatalf("unexpected failed result error: %v", err)
	}
	if session.Status != InstallStatusFailed {
		t.Fatalf("expected failed status, got %q", session.Status)
	}
	if session.ReasonCode != "BootstrapError" {
		t.Fatalf("expected failure reason to be set")
	}
}
