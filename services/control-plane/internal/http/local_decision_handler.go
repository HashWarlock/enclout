package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"enclout/services/control-plane/internal/requests"
)

type LocalDecisionBody struct {
	Approved bool `json:"approved"`
}

func (h *Handler) LocalDecision(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/connection-requests/", "/local-decision")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	var body LocalDecisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	updated, err := h.store.SetLocalDecision(id, body.Approved)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "request_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "decision_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
