package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound          = errors.New("request not found")
	ErrInvalidTransition = errors.New("invalid status transition")
	ErrExpired           = errors.New("request expired")
)

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type InMemoryStore struct {
	mu              sync.RWMutex
	items           map[string]ConnectionRequest
	installSessions map[string]InstallSession
	installTokens   map[string]string
	clock           clock
}

func NewInMemoryStore() *InMemoryStore {
	return NewInMemoryStoreWithClock(realClock{})
}

func NewInMemoryStoreWithClock(c clock) *InMemoryStore {
	return &InMemoryStore{
		items:           map[string]ConnectionRequest{},
		installSessions: map[string]InstallSession{},
		installTokens:   map[string]string{},
		clock:           c,
	}
}

func (s *InMemoryStore) now() time.Time {
	return s.clock.Now().UTC()
}

func (s *InMemoryStore) Create(in CreateInput) (ConnectionRequest, error) {
	if in.OpenClawUserID == "" || in.DeviceID == "" || in.ConnectorID == "" {
		return ConnectionRequest{}, fmt.Errorf("missing required fields")
	}
	if in.TTL <= 0 {
		return ConnectionRequest{}, fmt.Errorf("ttl must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	req := ConnectionRequest{
		ID:             randomID(),
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		Status:         StatusPendingLocalConfirm,
		CreatedAt:      now,
		ExpiresAt:      now.Add(in.TTL),
		Nonce:          randomID(),
	}

	s.items[req.ID] = req
	return req, nil
}

func (s *InMemoryStore) Get(id string) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.items[id]
	if !ok {
		return ConnectionRequest{}, ErrNotFound
	}

	req = s.expireIfNeeded(req)
	s.items[id] = req
	return req, nil
}

func (s *InMemoryStore) ListPendingForDevice(deviceID string) []ConnectionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ConnectionRequest, 0)
	for id, req := range s.items {
		req = s.expireIfNeeded(req)
		s.items[id] = req
		if req.DeviceID == deviceID && req.Status == StatusPendingLocalConfirm {
			out = append(out, req)
		}
	}
	return out
}

func (s *InMemoryStore) SetLocalDecision(id string, approved bool) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.items[id]
	if !ok {
		return ConnectionRequest{}, ErrNotFound
	}
	req = s.expireIfNeeded(req)
	if req.Status == StatusExpired {
		s.items[id] = req
		return ConnectionRequest{}, ErrExpired
	}
	if req.Status != StatusPendingLocalConfirm {
		return ConnectionRequest{}, ErrInvalidTransition
	}

	if approved {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDeniedLocal
	}
	s.items[id] = req
	return req, nil
}

func (s *InMemoryStore) SetResult(id string, status Status, reasonCode string) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.items[id]
	if !ok {
		return ConnectionRequest{}, ErrNotFound
	}
	req = s.expireIfNeeded(req)
	if req.Status == StatusExpired {
		s.items[id] = req
		return ConnectionRequest{}, ErrExpired
	}
	if req.Status != StatusApproved {
		return ConnectionRequest{}, ErrInvalidTransition
	}
	if status != StatusConnected && status != StatusVerificationFailed {
		return ConnectionRequest{}, ErrInvalidTransition
	}

	req.Status = status
	req.ReasonCode = reasonCode
	s.items[id] = req
	return req, nil
}

func (s *InMemoryStore) expireIfNeeded(req ConnectionRequest) ConnectionRequest {
	now := s.now()
	if now.After(req.ExpiresAt) &&
		req.Status != StatusExpired &&
		req.Status != StatusConnected &&
		req.Status != StatusDeniedLocal &&
		req.Status != StatusVerificationFailed {
		req.Status = StatusExpired
	}
	return req
}

func (s *InMemoryStore) CreateInstallSession(in CreateInstallInput) (InstallSession, string, error) {
	if in.OpenClawUserID == "" {
		return InstallSession{}, "", fmt.Errorf("missing required fields")
	}
	if in.TTL <= 0 {
		return InstallSession{}, "", fmt.Errorf("ttl must be positive")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	session := InstallSession{
		ID:             randomID(),
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		Status:         InstallStatusRequested,
		CreatedAt:      now,
		ExpiresAt:      now.Add(in.TTL),
	}
	token := randomID()
	tokenDigest := digestInstallToken(token)

	s.installSessions[session.ID] = session
	s.installTokens[tokenDigest] = session.ID

	return session, token, nil
}

func (s *InMemoryStore) GetInstallSession(id string) (InstallSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.installSessions[id]
	if !ok {
		return InstallSession{}, ErrNotFound
	}

	session, expired := s.expireInstallIfNeeded(session)
	if expired {
		s.deleteInstallTokensForSessionLocked(session.ID)
	}
	s.installSessions[id] = session

	return session, nil
}

func (s *InMemoryStore) SetInstallIdentity(id string, connectorID string, deviceID string) (InstallSession, error) {
	if strings.TrimSpace(connectorID) == "" || strings.TrimSpace(deviceID) == "" {
		return InstallSession{}, fmt.Errorf("missing required fields")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.installSessions[id]
	if !ok {
		return InstallSession{}, ErrNotFound
	}
	session, expired := s.expireInstallIfNeeded(session)
	if expired {
		s.deleteInstallTokensForSessionLocked(session.ID)
		s.installSessions[id] = session
		return session, ErrExpired
	}
	if session.Status != InstallStatusRequested && session.Status != InstallStatusApproved {
		return InstallSession{}, ErrInvalidTransition
	}

	session.ConnectorID = strings.TrimSpace(connectorID)
	session.DeviceID = strings.TrimSpace(deviceID)
	s.installSessions[id] = session
	return session, nil
}

func (s *InMemoryStore) SetInstallApproval(id string, approved bool) (InstallSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.installSessions[id]
	if !ok {
		return InstallSession{}, ErrNotFound
	}
	session, expired := s.expireInstallIfNeeded(session)
	if expired {
		s.deleteInstallTokensForSessionLocked(session.ID)
		s.installSessions[id] = session
		return session, ErrExpired
	}
	if session.Status != InstallStatusRequested {
		return InstallSession{}, ErrInvalidTransition
	}

	if approved {
		session.Status = InstallStatusApproved
	} else {
		session.Status = InstallStatusFailed
		session.ReasonCode = "Denied"
		s.deleteInstallTokensForSessionLocked(session.ID)
	}

	s.installSessions[id] = session
	return session, nil
}

func (s *InMemoryStore) SetInstallResult(id string, status InstallStatus, reasonCode string) (InstallSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.installSessions[id]
	if !ok {
		return InstallSession{}, ErrNotFound
	}
	session, expired := s.expireInstallIfNeeded(session)
	if expired {
		s.deleteInstallTokensForSessionLocked(session.ID)
		s.installSessions[id] = session
		return session, ErrExpired
	}
	if session.Status != InstallStatusApproved {
		return InstallSession{}, ErrInvalidTransition
	}
	if status != InstallStatusInstalled && status != InstallStatusFailed {
		return InstallSession{}, ErrInvalidTransition
	}
	if status == InstallStatusInstalled && (strings.TrimSpace(session.ConnectorID) == "" || strings.TrimSpace(session.DeviceID) == "") {
		return InstallSession{}, ErrInvalidTransition
	}

	session.Status = status
	session.ReasonCode = reasonCode
	s.installSessions[id] = session
	s.deleteInstallTokensForSessionLocked(session.ID)
	return session, nil
}

func (s *InMemoryStore) RedeemInstallToken(token string) (InstallSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionID, ok := s.installTokens[digestInstallToken(token)]
	if !ok {
		return InstallSession{}, ErrNotFound
	}

	session, ok := s.installSessions[sessionID]
	if !ok {
		return InstallSession{}, ErrNotFound
	}
	session, expired := s.expireInstallIfNeeded(session)
	if expired {
		s.deleteInstallTokensForSessionLocked(session.ID)
		s.installSessions[sessionID] = session
		return session, ErrExpired
	}
	if session.Status != InstallStatusApproved {
		return InstallSession{}, ErrInvalidTransition
	}

	s.deleteInstallTokensForSessionLocked(session.ID)
	return session, nil
}

func (s *InMemoryStore) expireInstallIfNeeded(session InstallSession) (InstallSession, bool) {
	now := s.now()
	if now.After(session.ExpiresAt) &&
		session.Status != InstallStatusInstalled &&
		session.Status != InstallStatusFailed {
		session.Status = InstallStatusFailed
		if session.ReasonCode == "" {
			session.ReasonCode = "Expired"
		}
		return session, true
	}
	return session, false
}

func (s *InMemoryStore) deleteInstallTokensForSessionLocked(sessionID string) {
	for tokenDigest, sid := range s.installTokens {
		if sid == sessionID {
			delete(s.installTokens, tokenDigest)
		}
	}
}

func digestInstallToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
