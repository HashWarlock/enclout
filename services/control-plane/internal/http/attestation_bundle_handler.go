package handlers

import (
	"errors"
	"net/http"
	"time"

	"enclout/services/control-plane/internal/requests"
	"enclout/services/control-plane/internal/signing"
)

func (h *Handler) AttestationBundle(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDFromPath(r.URL.Path, "/v1/connection-requests/", "/attestation-bundle")
	if err != nil {
		http.Error(w, "invalid_path", http.StatusBadRequest)
		return
	}

	req, err := h.store.Get(id)
	if err != nil {
		switch {
		case errors.Is(err, requests.ErrNotFound):
			http.Error(w, "not_found", http.StatusNotFound)
		default:
			http.Error(w, "request_lookup_failed", http.StatusInternalServerError)
		}
		return
	}

	if req.Status != requests.StatusApproved {
		http.Error(w, "request_not_approved", http.StatusConflict)
		return
	}

	tpl, err := h.bundles.GetBundle(req.ConnectorID)
	if err != nil {
		http.Error(w, "bundle_not_found", http.StatusNotFound)
		return
	}

	now := h.nowFn().UTC()
	expiresAt := req.ExpiresAt
	if expiresAt.Before(now) {
		http.Error(w, "request_expired", http.StatusGone)
		return
	}

	payload := signing.BundlePayload{
		RequestID:                req.ID,
		ConnectorID:              tpl.ConnectorID,
		SSHPublicKey:             tpl.SSHPublicKey,
		QuoteHex:                 tpl.QuoteHex,
		EventLog:                 tpl.EventLog,
		MRTD:                     tpl.MRTD,
		RTMR0:                    tpl.RTMR0,
		RTMR1:                    tpl.RTMR1,
		RTMR2:                    tpl.RTMR2,
		RTMR3:                    tpl.RTMR3,
		ReportDataExpectedSHA256: signing.ReportDataHashFromSSHPublicKey(tpl.SSHPublicKey),
		PolicyVersion:            policyVersionOrDefault(tpl.PolicyVersion),
		IssuedAt:                 now,
		ExpiresAt:                expiresAt,
		Nonce:                    req.Nonce,
	}

	signed, err := h.signer.SignBundle(payload)
	if err != nil {
		http.Error(w, "bundle_signing_failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, signed)
}

func policyVersionOrDefault(v string) string {
	if v == "" {
		return "v1"
	}
	return v
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
