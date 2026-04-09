package access

import (
	"errors"
	"testing"
	"time"
)

func TestNewConnectionRequest(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)

	if cr.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if cr.RequesterID != "user-1" {
		t.Fatalf("expected RequesterID %q, got %q", "user-1", cr.RequesterID)
	}
	if cr.DeviceID != "device-1" {
		t.Fatalf("expected DeviceID %q, got %q", "device-1", cr.DeviceID)
	}
	if cr.ConnectorID != "connector-1" {
		t.Fatalf("expected ConnectorID %q, got %q", "connector-1", cr.ConnectorID)
	}
	if cr.Source != "slack" {
		t.Fatalf("expected Source %q, got %q", "slack", cr.Source)
	}
	if cr.Status != StatusPendingLocalConfirm {
		t.Fatalf("expected Status %q, got %q", StatusPendingLocalConfirm, cr.Status)
	}
	if cr.CreatedAt.IsZero() {
		t.Fatal("expected non-zero CreatedAt")
	}
	if cr.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}
	if cr.ExpiresAt.Sub(cr.CreatedAt) != 15*time.Minute {
		t.Fatalf("expected TTL of 15m, got %v", cr.ExpiresAt.Sub(cr.CreatedAt))
	}
	if cr.Nonce == "" {
		t.Fatal("expected non-empty Nonce")
	}
	if cr.Nonce == cr.ID {
		t.Fatal("Nonce should differ from ID")
	}
}

func TestConnectionRequest_Approve(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)

	if err := cr.Approve(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Status != StatusApproved {
		t.Fatalf("expected Status %q, got %q", StatusApproved, cr.Status)
	}
}

func TestConnectionRequest_Approve_WrongState(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
	_ = cr.Approve() // move to approved

	err := cr.Approve()
	if err == nil {
		t.Fatal("expected error when approving from approved state")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}

func TestConnectionRequest_Deny(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)

	if err := cr.Deny(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Status != StatusDeniedLocal {
		t.Fatalf("expected Status %q, got %q", StatusDeniedLocal, cr.Status)
	}
}

func TestConnectionRequest_Revoke(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
	_ = cr.Approve()

	if err := cr.Revoke(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Status != StatusRevoked {
		t.Fatalf("expected Status %q, got %q", StatusRevoked, cr.Status)
	}
}

func TestConnectionRequest_SetResult_Connected(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
	_ = cr.Approve()

	if err := cr.SetResult(StatusConnected, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Status != StatusConnected {
		t.Fatalf("expected Status %q, got %q", StatusConnected, cr.Status)
	}
}

func TestConnectionRequest_SetResult_VerificationFailed(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
	_ = cr.Approve()

	if err := cr.SetResult(StatusVerificationFailed, "attestation_mismatch"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr.Status != StatusVerificationFailed {
		t.Fatalf("expected Status %q, got %q", StatusVerificationFailed, cr.Status)
	}
	if cr.ReasonCode != "attestation_mismatch" {
		t.Fatalf("expected ReasonCode %q, got %q", "attestation_mismatch", cr.ReasonCode)
	}
}

func TestConnectionRequest_Expire(t *testing.T) {
	t.Run("from pending", func(t *testing.T) {
		cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
		if err := cr.Expire(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cr.Status != StatusExpired {
			t.Fatalf("expected Status %q, got %q", StatusExpired, cr.Status)
		}
	})

	t.Run("from approved", func(t *testing.T) {
		cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
		_ = cr.Approve()
		if err := cr.Expire(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cr.Status != StatusExpired {
			t.Fatalf("expected Status %q, got %q", StatusExpired, cr.Status)
		}
	})
}

func TestConnectionRequest_Expire_FromTerminalState(t *testing.T) {
	t.Run("from connected", func(t *testing.T) {
		cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
		_ = cr.Approve()
		_ = cr.SetResult(StatusConnected, "")

		err := cr.Expire()
		if err == nil {
			t.Fatal("expected error when expiring from connected state")
		}
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("expected ErrInvalidTransition, got %v", err)
		}
	})

	t.Run("from denied", func(t *testing.T) {
		cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
		_ = cr.Deny()

		err := cr.Expire()
		if err == nil {
			t.Fatal("expected error when expiring from denied state")
		}
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("expected ErrInvalidTransition, got %v", err)
		}
	})
}

func TestConnectionRequest_Revoke_FromTerminalState(t *testing.T) {
	cr := NewConnectionRequest("user-1", "device-1", "connector-1", "slack", 15*time.Minute)
	_ = cr.Approve()
	_ = cr.SetResult(StatusConnected, "")

	err := cr.Revoke()
	if err == nil {
		t.Fatal("expected error when revoking from connected state")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}
}
