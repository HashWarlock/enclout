package requests

import (
	"errors"
	"fmt"
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
	mu    sync.RWMutex
	items map[string]ConnectionRequest
	clock clock
}

func NewInMemoryStore() *InMemoryStore {
	return NewInMemoryStoreWithClock(realClock{})
}

func NewInMemoryStoreWithClock(c clock) *InMemoryStore {
	return &InMemoryStore{
		items: map[string]ConnectionRequest{},
		clock: c,
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
