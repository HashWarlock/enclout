package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"enclout/services/control-plane/internal/requests"
)

type CreateInstallSessionBody struct {
	OpenClawUserID string `json:"openclaw_user_id"`
	DeviceID       string `json:"device_id"`
	ConnectorID    string `json:"connector_id"`
	SourceChannel  string `json:"source_channel"`
}

type createInstallSessionResponse struct {
	requests.InstallSession
	InstallToken string `json:"install_token"`
}

func (h *Handler) CreateInstallSession(w http.ResponseWriter, r *http.Request) {
	var in CreateInstallSessionBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	session, token, err := h.store.CreateInstallSession(requests.CreateInstallInput{
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

	writeJSON(w, http.StatusCreated, createInstallSessionResponse{
		InstallSession: session,
		InstallToken:   token,
	})
}

type InstallApprovalBody struct {
	Approved bool `json:"approved"`
}

func (h *Handler) InstallSessionApproval(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/install-sessions/", "/approval")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	var body InstallApprovalBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	updated, err := h.store.SetInstallApproval(id, body.Approved)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "install_session_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "approval_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

type RedeemInstallTokenBody struct {
	Token string `json:"token"`
}

func (h *Handler) RedeemInstallToken(w http.ResponseWriter, r *http.Request) {
	var body RedeemInstallTokenBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	session, err := h.store.RedeemInstallToken(body.Token)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "install_session_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "redeem_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, session)
}

type InstallSessionResultBody struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

type InstallSessionRegistrationBody struct {
	ConnectorID string `json:"connector_id"`
	DeviceID    string `json:"device_id"`
}

func (h *Handler) GetInstallSession(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/install-sessions/", "")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	session, err := h.store.GetInstallSession(id)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "install_session_expired", http.StatusGone)
		default:
			http.Error(w, "get_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, session)
}

func (h *Handler) InstallSessionResult(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/install-sessions/", "/result")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	var body InstallSessionResultBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	status := requests.InstallStatus(body.Status)
	updated, err := h.store.SetInstallResult(id, status, body.ReasonCode)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "install_session_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "result_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) InstallSessionRegistration(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/install-sessions/", "/registration")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	var body InstallSessionRegistrationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	updated, err := h.store.SetInstallIdentity(id, body.ConnectorID, body.DeviceID)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "install_session_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "registration_failed", http.StatusBadRequest)
		}
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
