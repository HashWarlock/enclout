package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"enclout/services/control-plane/internal/requests"
	"enclout/services/control-plane/internal/signing"
)

const (
	DefaultRequestTTL = 5 * time.Minute
)

type RequestStore interface {
	Create(in requests.CreateInput) (requests.ConnectionRequest, error)
	Get(id string) (requests.ConnectionRequest, error)
	SetLocalDecision(id string, approved bool) (requests.ConnectionRequest, error)
	SetResult(id string, status requests.Status, reasonCode string) (requests.ConnectionRequest, error)
	ListPendingForDevice(deviceID string) []requests.ConnectionRequest
}

type BundleTemplate struct {
	ConnectorID   string
	SSHPublicKey  string
	QuoteHex      string
	EventLog      string
	MRTD          string
	RTMR0         string
	RTMR1         string
	RTMR2         string
	RTMR3         string
	PolicyVersion string
}

type BundleSource interface {
	GetBundle(connectorID string) (BundleTemplate, error)
}

type StaticBundleSource struct {
	byConnector map[string]BundleTemplate
}

func NewStaticBundleSource(initial map[string]BundleTemplate) *StaticBundleSource {
	cloned := make(map[string]BundleTemplate, len(initial))
	for k, v := range initial {
		cloned[k] = v
	}
	return &StaticBundleSource{byConnector: cloned}
}

func (s *StaticBundleSource) GetBundle(connectorID string) (BundleTemplate, error) {
	v, ok := s.byConnector[connectorID]
	if !ok {
		return BundleTemplate{}, errors.New("bundle not found")
	}
	return v, nil
}

type Handler struct {
	store      RequestStore
	signer     *signing.Ed25519Signer
	bundles    BundleSource
	nowFn      func() time.Time
	requestTTL time.Duration
}

func NewHandler(store RequestStore, signer *signing.Ed25519Signer, bundles BundleSource) *Handler {
	return &Handler{
		store:      store,
		signer:     signer,
		bundles:    bundles,
		nowFn:      time.Now,
		requestTTL: DefaultRequestTTL,
	}
}

func (h *Handler) SetNow(nowFn func() time.Time) {
	h.nowFn = nowFn
}

func (h *Handler) SetTTL(ttl time.Duration) {
	h.requestTTL = ttl
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func parseIDFromPath(path string, prefix string, suffix string) (string, error) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", errors.New("invalid path")
	}
	s := strings.TrimPrefix(path, prefix)
	s = strings.TrimSuffix(s, suffix)
	if s == "" || strings.Contains(s, "/") {
		return "", errors.New("invalid id")
	}
	return s, nil
}
