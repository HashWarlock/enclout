package openclaw

import (
	"encoding/json"
	"net/http"
	"time"

	"enclout/services/control-plane/internal/requests"
)

const RequestIntent = "request_connector_access"
const InstallRequestIntent = "request_connector_install"
const InstallApprovalIntent = "approve_install_session"
const InstallResultIntent = "install_session_result"

type RequestStore interface {
	Create(in requests.CreateInput) (requests.ConnectionRequest, error)
	CreateInstallSession(in requests.CreateInstallInput) (requests.InstallSession, string, error)
	SetInstallApproval(id string, approved bool) (requests.InstallSession, error)
	SetInstallResult(id string, status requests.InstallStatus, reasonCode string) (requests.InstallSession, error)
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
	Intent           string `json:"intent"`
	OpenClawUserID   string `json:"openclaw_user_id"`
	ConnectorID      string `json:"connector_id"`
	DeviceID         string `json:"device_id"`
	SourceChannel    string `json:"source_channel"`
	InstallSessionID string `json:"install_session_id"`
	Approved         bool   `json:"approved"`
	Status           string `json:"status"`
	ReasonCode       string `json:"reason_code"`
}

func (h *IntentHandler) Handle(w http.ResponseWriter, r *http.Request) {
	var payload IntentBody
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}
	switch payload.Intent {
	case RequestIntent:
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
	case InstallRequestIntent:
		session, token, err := h.store.CreateInstallSession(requests.CreateInstallInput{
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
		_ = json.NewEncoder(w).Encode(struct {
			requests.InstallSession
			InstallToken string `json:"install_token"`
		}{
			InstallSession: session,
			InstallToken:   token,
		})
	case InstallApprovalIntent:
		updated, err := h.store.SetInstallApproval(payload.InstallSessionID, payload.Approved)
		if err != nil {
			http.Error(w, "update_failed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(updated)
	case InstallResultIntent:
		updated, err := h.store.SetInstallResult(payload.InstallSessionID, requests.InstallStatus(payload.Status), payload.ReasonCode)
		if err != nil {
			http.Error(w, "update_failed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(updated)
	default:
		http.Error(w, "unsupported_intent", http.StatusBadRequest)
	}
}
