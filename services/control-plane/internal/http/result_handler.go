package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"enclout/services/control-plane/internal/requests"
)

type ResultBody struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

func (h *Handler) Result(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/connection-requests/", "/result")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	var body ResultBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid_json", http.StatusBadRequest)
		return
	}

	status := requests.Status(body.Status)
	updated, err := h.store.SetResult(id, status, body.ReasonCode)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		case errors.Is(err, requests.ErrExpired):
			http.Error(w, "request_expired", http.StatusGone)
		case errors.Is(err, requests.ErrInvalidTransition):
			http.Error(w, "invalid_transition", http.StatusConflict)
		default:
			http.Error(w, "result_failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, http.StatusOK, updated)
}
