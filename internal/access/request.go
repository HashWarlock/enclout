package access

import "time"

type Status string

const (
	StatusPendingLocalConfirm Status = "pending_local_confirm"
	StatusApproved            Status = "approved"
	StatusDeniedLocal         Status = "denied_local"
	StatusRevoked             Status = "revoked"
	StatusExpired             Status = "expired"
	StatusVerificationFailed  Status = "verification_failed"
	StatusConnected           Status = "connected"
)

type ConnectionRequest struct {
	ID          string
	RequesterID string
	DeviceID    string
	ConnectorID string
	Source      string
	Status      Status
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Nonce       string
	ReasonCode  string
}

func NewConnectionRequest(requesterID, deviceID, connectorID, source string, ttl time.Duration) ConnectionRequest {
	now := time.Now().UTC()
	return ConnectionRequest{
		ID:          RandomID(),
		RequesterID: requesterID,
		DeviceID:    deviceID,
		ConnectorID: connectorID,
		Source:      source,
		Status:      StatusPendingLocalConfirm,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		Nonce:       RandomID(),
	}
}

func (r *ConnectionRequest) Approve() error {
	if r.Status != StatusPendingLocalConfirm {
		return ErrInvalidTransition
	}
	r.Status = StatusApproved
	return nil
}

func (r *ConnectionRequest) Deny() error {
	if r.Status != StatusPendingLocalConfirm {
		return ErrInvalidTransition
	}
	r.Status = StatusDeniedLocal
	return nil
}

func (r *ConnectionRequest) Revoke() error {
	if r.Status != StatusPendingLocalConfirm && r.Status != StatusApproved {
		return ErrInvalidTransition
	}
	r.Status = StatusRevoked
	return nil
}

func (r *ConnectionRequest) Expire() error {
	if r.Status != StatusPendingLocalConfirm && r.Status != StatusApproved {
		return ErrInvalidTransition
	}
	r.Status = StatusExpired
	return nil
}

func (r *ConnectionRequest) SetResult(status Status, reasonCode string) error {
	if r.Status != StatusApproved {
		return ErrInvalidTransition
	}
	if status != StatusConnected && status != StatusVerificationFailed {
		return ErrInvalidTransition
	}
	r.Status = status
	r.ReasonCode = reasonCode
	return nil
}
