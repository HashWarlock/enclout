package handlers

import "net/http"

func (h *Handler) SigningKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.signer.Keyset())
}
