package access

import (
	"fmt"
	"strings"
	"time"
)

type InstallStatus string

const (
	InstallStatusRequested InstallStatus = "requested"
	InstallStatusApproved  InstallStatus = "approved"
	InstallStatusInstalled InstallStatus = "installed"
	InstallStatusFailed    InstallStatus = "failed"
)

type InstallSession struct {
	ID          string
	RequesterID string
	DeviceID    string
	ConnectorID string
	Source      string
	Status      InstallStatus
	TokenDigest string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ReasonCode  string
}

// NewInstallSession creates a session and returns it along with the raw (unhashed) token.
func NewInstallSession(requesterID, source string, ttl time.Duration) (InstallSession, string) {
	now := time.Now().UTC()
	rawToken := RandomID()
	return InstallSession{
		ID:          RandomID(),
		RequesterID: requesterID,
		Source:      source,
		Status:      InstallStatusRequested,
		TokenDigest: DigestToken(rawToken),
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}, rawToken
}

func (s *InstallSession) Approve() error {
	if s.Status != InstallStatusRequested {
		return ErrInvalidTransition
	}
	s.Status = InstallStatusApproved
	return nil
}

func (s *InstallSession) Deny() error {
	if s.Status != InstallStatusRequested {
		return ErrInvalidTransition
	}
	s.Status = InstallStatusFailed
	s.ReasonCode = "Denied"
	return nil
}

func (s *InstallSession) Register(connectorID, deviceID string) error {
	connectorID = strings.TrimSpace(connectorID)
	deviceID = strings.TrimSpace(deviceID)
	if connectorID == "" || deviceID == "" {
		return fmt.Errorf("connectorID and deviceID are required")
	}
	if s.Status != InstallStatusRequested && s.Status != InstallStatusApproved {
		return ErrInvalidTransition
	}
	s.ConnectorID = connectorID
	s.DeviceID = deviceID
	return nil
}

func (s *InstallSession) Complete() error {
	if s.Status != InstallStatusApproved {
		return ErrInvalidTransition
	}
	if strings.TrimSpace(s.ConnectorID) == "" || strings.TrimSpace(s.DeviceID) == "" {
		return fmt.Errorf("identity must be registered before completing")
	}
	s.Status = InstallStatusInstalled
	return nil
}

func (s *InstallSession) Fail(reason string) error {
	if s.Status != InstallStatusApproved {
		return ErrInvalidTransition
	}
	s.Status = InstallStatusFailed
	s.ReasonCode = reason
	return nil
}

func (s *InstallSession) Expire() error {
	if s.Status != InstallStatusRequested && s.Status != InstallStatusApproved {
		return ErrInvalidTransition
	}
	s.Status = InstallStatusFailed
	s.ReasonCode = "Expired"
	return nil
}
