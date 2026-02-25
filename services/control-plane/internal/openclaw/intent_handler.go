package openclaw

import (
	"encoding/json"
	"net/http"
	"time"

	"enclout/services/control-plane/internal/requests"
)

const RequestIntent = "request_connector_access"

type RequestStore interface {
	Create(in requests.CreateInput) (requests.ConnectionRequest, error)
}

type IntentHandler struct {
	store      RequestStore
	requestTTL time.Duration
}

func NewIntentHandler(store RequestStore) *IntentHandler {
	return &IntentHandler{
		store:      store,
		requestTTL: 5 * time.Minute,
	}
}

type IntentBody struct {
	Intent         string `json:"intent"`
	OpenClawUserID string `json:"openclaw_user_id"`
	ConnectorID    string `json:"connector_id"`
	DeviceID       string `json:"device_id"`
	SourceChannel  string `json:"source_channel"`
}

func (h *IntentHandler) Handle(w http.ResponseWriter, r *http.Request) {
	var payload IntentBody
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}
	if payload.Intent != RequestIntent {
		http.Error(w, "unsupported_intent", http.StatusBadRequest)
		return
	}

	req, err := h.store.Create(requests.CreateInput{
		OpenClawUserID: payload.OpenClawUserID,
		DeviceID:       payload.DeviceID,
		ConnectorID:    payload.ConnectorID,
		SourceChannel:  payload.SourceChannel,
		TTL:            h.requestTTL,
	})
	if err != nil {
		http.Error(w, "create_failed", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(req)
}
