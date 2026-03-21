package access

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewInstallSession(t *testing.T) {
	sess, rawToken := NewInstallSession("req-1", "cli", 10*time.Minute)

	if sess.Status != InstallStatusRequested {
		t.Fatalf("expected status %q, got %q", InstallStatusRequested, sess.Status)
	}
	if sess.RequesterID != "req-1" {
		t.Fatalf("expected requesterID %q, got %q", "req-1", sess.RequesterID)
	}
	if sess.Source != "cli" {
		t.Fatalf("expected source %q, got %q", "cli", sess.Source)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if rawToken == "" {
		t.Fatal("expected non-empty raw token")
	}
	if sess.TokenDigest == "" {
		t.Fatal("expected non-empty token digest")
	}
	// Digest must match the raw token
	if sess.TokenDigest != DigestToken(rawToken) {
		t.Fatalf("token digest mismatch: got %q, want DigestToken(%q)=%q", sess.TokenDigest, rawToken, DigestToken(rawToken))
	}
	if sess.ExpiresAt.Before(sess.CreatedAt) {
		t.Fatal("expiresAt should be after createdAt")
	}
}

func TestInstallSession_Approve(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	if err := sess.Approve(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Status != InstallStatusApproved {
		t.Fatalf("expected status %q, got %q", InstallStatusApproved, sess.Status)
	}
}

func TestInstallSession_Approve_WrongState(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	_ = sess.Approve() // requested -> approved

	err := sess.Approve() // approved -> approved (invalid)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestInstallSession_Deny(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	if err := sess.Deny(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Status != InstallStatusFailed {
		t.Fatalf("expected status %q, got %q", InstallStatusFailed, sess.Status)
	}
	if sess.ReasonCode != "Denied" {
		t.Fatalf("expected reason %q, got %q", "Denied", sess.ReasonCode)
	}
}

func TestInstallSession_Register(t *testing.T) {
	// From requested state
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	if err := sess.Register("conn-1", "dev-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.ConnectorID != "conn-1" {
		t.Fatalf("expected connectorID %q, got %q", "conn-1", sess.ConnectorID)
	}
	if sess.DeviceID != "dev-1" {
		t.Fatalf("expected deviceID %q, got %q", "dev-1", sess.DeviceID)
	}
	// Status should not change
	if sess.Status != InstallStatusRequested {
		t.Fatalf("expected status %q, got %q", InstallStatusRequested, sess.Status)
	}

	// From approved state
	sess2, _ := NewInstallSession("req-2", "web", 10*time.Minute)
	_ = sess2.Approve()
	if err := sess2.Register("conn-2", "dev-2"); err != nil {
		t.Fatalf("unexpected error from approved state: %v", err)
	}
	if sess2.Status != InstallStatusApproved {
		t.Fatalf("expected status %q, got %q", InstallStatusApproved, sess2.Status)
	}
}

func TestInstallSession_Register_TerminalState(t *testing.T) {
	// From installed state
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	_ = sess.Register("conn-1", "dev-1")
	_ = sess.Approve()
	_ = sess.Complete()
	err := sess.Register("conn-2", "dev-2")
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition from installed, got %v", err)
	}

	// From failed state
	sess2, _ := NewInstallSession("req-2", "web", 10*time.Minute)
	_ = sess2.Deny()
	err = sess2.Register("conn-2", "dev-2")
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition from failed, got %v", err)
	}
}

func TestInstallSession_Register_EmptyFields(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)

	if err := sess.Register("", "dev-1"); err == nil {
		t.Fatal("expected error for empty connectorID")
	}
	if err := sess.Register("conn-1", ""); err == nil {
		t.Fatal("expected error for empty deviceID")
	}
	if err := sess.Register("  ", "dev-1"); err == nil {
		t.Fatal("expected error for whitespace-only connectorID")
	}
	if err := sess.Register("conn-1", "  "); err == nil {
		t.Fatal("expected error for whitespace-only deviceID")
	}
}

func TestInstallSession_Complete(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	_ = sess.Register("conn-1", "dev-1")
	_ = sess.Approve()

	if err := sess.Complete(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Status != InstallStatusInstalled {
		t.Fatalf("expected status %q, got %q", InstallStatusInstalled, sess.Status)
	}
}

func TestInstallSession_Complete_NoIdentity(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	_ = sess.Approve()

	err := sess.Complete()
	if err == nil {
		t.Fatal("expected error when identity not registered")
	}
	if !strings.Contains(err.Error(), "identity must be registered") {
		t.Fatalf("expected identity registration error, got: %v", err)
	}
}

func TestInstallSession_Fail(t *testing.T) {
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	_ = sess.Approve()

	if err := sess.Fail("custom reason"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Status != InstallStatusFailed {
		t.Fatalf("expected status %q, got %q", InstallStatusFailed, sess.Status)
	}
	if sess.ReasonCode != "custom reason" {
		t.Fatalf("expected reason %q, got %q", "custom reason", sess.ReasonCode)
	}
}

func TestInstallSession_Expire(t *testing.T) {
	// From requested
	sess, _ := NewInstallSession("req-1", "cli", 10*time.Minute)
	if err := sess.Expire(); err != nil {
		t.Fatalf("unexpected error from requested: %v", err)
	}
	if sess.Status != InstallStatusFailed {
		t.Fatalf("expected status %q, got %q", InstallStatusFailed, sess.Status)
	}
	if sess.ReasonCode != "Expired" {
		t.Fatalf("expected reason %q, got %q", "Expired", sess.ReasonCode)
	}

	// From approved
	sess2, _ := NewInstallSession("req-2", "web", 10*time.Minute)
	_ = sess2.Approve()
	if err := sess2.Expire(); err != nil {
		t.Fatalf("unexpected error from approved: %v", err)
	}
	if sess2.Status != InstallStatusFailed {
		t.Fatalf("expected status %q, got %q", InstallStatusFailed, sess2.Status)
	}
	if sess2.ReasonCode != "Expired" {
		t.Fatalf("expected reason %q, got %q", "Expired", sess2.ReasonCode)
	}
}
