package requests

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type fileStoreState struct {
	Items map[string]ConnectionRequest `json:"items"`
}

type FileStore struct {
	mu   sync.Mutex
	path string
	mem  *InMemoryStore
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("store path is required")
	}

	mem := NewInMemoryStore()
	store := &FileStore{
		path: path,
		mem:  mem,
	}

	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileStore) Create(in CreateInput) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.mem.Create(in)
	if err != nil {
		return ConnectionRequest{}, err
	}
	if err := s.persistLocked(); err != nil {
		return ConnectionRequest{}, err
	}
	return req, nil
}

func (s *FileStore) Get(id string) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.mem.Get(id)
	if err != nil {
		return ConnectionRequest{}, err
	}
	_ = s.persistLocked()
	return req, nil
}

func (s *FileStore) ListPendingForDevice(deviceID string) []ConnectionRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := s.mem.ListPendingForDevice(deviceID)
	_ = s.persistLocked()
	return items
}

func (s *FileStore) SetLocalDecision(id string, approved bool) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.mem.SetLocalDecision(id, approved)
	if err != nil {
		return ConnectionRequest{}, err
	}
	if err := s.persistLocked(); err != nil {
		return ConnectionRequest{}, err
	}
	return req, nil
}

func (s *FileStore) SetResult(id string, status Status, reasonCode string) (ConnectionRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.mem.SetResult(id, status, reasonCode)
	if err != nil {
		return ConnectionRequest{}, err
	}
	if err := s.persistLocked(); err != nil {
		return ConnectionRequest{}, err
	}
	return req, nil
}

func (s *FileStore) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var state fileStoreState
	if err := json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if state.Items == nil {
		state.Items = map[string]ConnectionRequest{}
	}

	s.mem.items = state.Items
	return nil
}

func (s *FileStore) persistLocked() error {
	state := fileStoreState{
		Items: s.mem.items,
	}

	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}
