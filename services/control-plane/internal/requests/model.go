package requests

import "time"

type Status string

const (
	StatusPendingLocalConfirm Status = "pending_local_confirm"
	StatusDeniedLocal         Status = "denied_local"
	StatusApproved            Status = "approved"
	StatusExpired             Status = "expired"
	StatusVerificationFailed  Status = "verification_failed"
	StatusConnected           Status = "connected"
)

type ConnectionRequest struct {
	ID             string    `json:"id"`
	OpenClawUserID string    `json:"openclaw_user_id"`
	DeviceID       string    `json:"device_id"`
	ConnectorID    string    `json:"connector_id"`
	SourceChannel  string    `json:"source_channel"`
	Status         Status    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Nonce          string    `json:"nonce"`
	ReasonCode     string    `json:"reason_code,omitempty"`
}

type CreateInput struct {
	OpenClawUserID string
	DeviceID       string
	ConnectorID    string
	SourceChannel  string
	TTL            time.Duration
}

type InstallStatus string

const (
	InstallStatusRequested InstallStatus = "requested"
	InstallStatusApproved  InstallStatus = "approved"
	InstallStatusInstalled InstallStatus = "installed"
	InstallStatusFailed    InstallStatus = "failed"
)

type InstallSession struct {
	ID             string        `json:"id"`
	OpenClawUserID string        `json:"openclaw_user_id"`
	DeviceID       string        `json:"device_id"`
	ConnectorID    string        `json:"connector_id"`
	SourceChannel  string        `json:"source_channel"`
	Status         InstallStatus `json:"status"`
	CreatedAt      time.Time     `json:"created_at"`
	ExpiresAt      time.Time     `json:"expires_at"`
	ReasonCode     string        `json:"reason_code,omitempty"`
}

type CreateInstallInput struct {
	OpenClawUserID string
	DeviceID       string
	ConnectorID    string
	SourceChannel  string
	TTL            time.Duration
}
