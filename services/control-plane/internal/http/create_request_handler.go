package handlers

import (
	"encoding/json"
	"net/http"

	"enclout/services/control-plane/internal/requests"
)

type CreateRequestBody struct {
	OpenClawUserID string `json:"openclaw_user_id"`
	DeviceID       string `json:"device_id"`
	ConnectorID    string `json:"connector_id"`
	SourceChannel  string `json:"source_channel"`
}

func (h *Handler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	var in CreateRequestBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	req, err := h.store.Create(requests.CreateInput{
		OpenClawUserID: in.OpenClawUserID,
		DeviceID:       in.DeviceID,
		ConnectorID:    in.ConnectorID,
		SourceChannel:  in.SourceChannel,
		TTL:            h.requestTTL,
	})
	if err != nil {
		http.Error(w, "create_failed", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusCreated, req)
}

func (h *Handler) ListPendingRequestsForDevice(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parseIDFromPath(r.URL.Path, "/v1/devices/", "/pending-requests")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	items := h.store.ListPendingForDevice(deviceID)
	writeJSON(w, http.StatusOK, items)
}
