package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"enclout/internal/access"
	"enclout/internal/signing"
	"enclout/internal/store"
)

const defaultRequestTTL = 5 * time.Minute

// Handlers implements all HTTP route handlers for the API.
type Handlers struct {
	requests *store.RequestRepository
	sessions *store.SessionRepository
	bundles  *store.BundleRepository
	audit    *store.AuditLogger
	signer   signing.BundleSigner
}

// NewHandlers creates a Handlers instance with all dependencies.
func NewHandlers(deps Deps) *Handlers {
	return &Handlers{
		requests: deps.Requests,
		sessions: deps.Sessions,
		bundles:  deps.Bundles,
		audit:    deps.Audit,
		signer:   deps.Signer,
	}
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- Connection Request handlers ---

type createRequestBody struct {
	RequesterID string `json:"requester_id"`
	DeviceID    string `json:"device_id"`
	ConnectorID string `json:"connector_id"`
	Source      string `json:"source"`
}

// CreateRequest handles POST /v1/requests.
func (h *Handlers) CreateRequest(w http.ResponseWriter, r *http.Request) {
	var body createRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if body.RequesterID == "" || body.DeviceID == "" || body.ConnectorID == "" {
		writeError(w, http.StatusBadRequest, "requester_id, device_id, and connector_id are required")
		return
	}

	req := access.NewConnectionRequest(body.RequesterID, body.DeviceID, body.ConnectorID, body.Source, defaultRequestTTL)
	if err := h.requests.Create(r.Context(), req); err != nil {
		writeError(w, http.StatusInternalServerError, "create_failed")
		return
	}

	_ = h.audit.Log(r.Context(), "connection_request", req.ID, "created", body.RequesterID, "")
	writeJSON(w, http.StatusCreated, req)
}

// GetRequest handles GET /v1/requests/{id}.
func (h *Handlers) GetRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, err := h.requests.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// ListRequests handles GET /v1/requests with optional filters and pagination.
func (h *Handlers) ListRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	offset := 0

	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_offset")
			return
		}
		offset = n
	}

	var status access.Status
	if raw := q.Get("status"); raw != "" {
		status = access.Status(raw)
		if !isRequestStatus(status) {
			writeError(w, http.StatusBadRequest, "invalid_status")
			return
		}
	}

	items, err := h.requests.List(r.Context(), store.RequestListOptions{
		DeviceID:    q.Get("device_id"),
		RequesterID: q.Get("requester_id"),
		Status:      status,
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	if items == nil {
		items = []access.ConnectionRequest{}
	}
	writeJSON(w, http.StatusOK, items)
}

type decisionBody struct {
	Approved bool `json:"approved"`
}

// PostDecision handles POST /v1/requests/{id}/decision.
func (h *Handlers) PostDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body decisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	next := access.StatusDeniedLocal
	if body.Approved {
		next = access.StatusApproved
	}

	req, err := h.requests.Transition(
		r.Context(),
		id,
		[]access.Status{access.StatusPendingLocalConfirm},
		next,
		"",
	)
	if err != nil {
		switch {
		case errors.Is(err, access.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found")
		case errors.Is(err, access.ErrInvalidTransition):
			writeError(w, http.StatusConflict, "invalid_transition")
		default:
			writeError(w, http.StatusInternalServerError, "update_failed")
		}
		return
	}

	action := "denied"
	if body.Approved {
		action = "approved"
	}
	_ = h.audit.Log(r.Context(), "connection_request", id, action, "", "")
	writeJSON(w, http.StatusOK, req)
}

// PostRevoke handles POST /v1/requests/{id}/revoke.
func (h *Handlers) PostRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	req, err := h.requests.Transition(
		r.Context(),
		id,
		[]access.Status{access.StatusPendingLocalConfirm, access.StatusApproved},
		access.StatusRevoked,
		"",
	)
	if err != nil {
		switch {
		case errors.Is(err, access.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found")
		case errors.Is(err, access.ErrInvalidTransition):
			writeError(w, http.StatusConflict, "invalid_transition")
		default:
			writeError(w, http.StatusInternalServerError, "update_failed")
		}
		return
	}

	_ = h.audit.Log(r.Context(), "connection_request", id, "revoked", "", "")
	writeJSON(w, http.StatusOK, req)
}

type resultBody struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

// PostResult handles POST /v1/requests/{id}/result.
func (h *Handlers) PostResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body resultBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	status := access.Status(body.Status)
	if status != access.StatusConnected && status != access.StatusVerificationFailed {
		writeError(w, http.StatusConflict, "invalid_transition")
		return
	}

	req, err := h.requests.Transition(
		r.Context(),
		id,
		[]access.Status{access.StatusApproved},
		status,
		body.ReasonCode,
	)
	if err != nil {
		switch {
		case errors.Is(err, access.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found")
		case errors.Is(err, access.ErrInvalidTransition):
			writeError(w, http.StatusConflict, "invalid_transition")
		default:
			writeError(w, http.StatusInternalServerError, "update_failed")
		}
		return
	}

	_ = h.audit.Log(r.Context(), "connection_request", id, "result:"+body.Status, "", body.ReasonCode)
	writeJSON(w, http.StatusOK, req)
}

// GetBundle handles GET /v1/requests/{id}/bundle.
func (h *Handlers) GetBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, err := h.requests.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}

	if req.Status != access.StatusApproved {
		writeError(w, http.StatusConflict, "request_not_approved")
		return
	}

	bundle, err := h.bundles.Get(r.Context(), req.ConnectorID)
	if err != nil {
		writeError(w, http.StatusNotFound, "bundle_not_found")
		return
	}

	now := time.Now().UTC()
	if req.ExpiresAt.Before(now) {
		writeError(w, http.StatusGone, "request_expired")
		return
	}

	payload := signing.BundlePayload{
		RequestID:                req.ID,
		ConnectorID:              bundle.ConnectorID,
		SSHPublicKey:             bundle.SSHPublicKey,
		QuoteHex:                 bundle.QuoteHex,
		EventLog:                 bundle.EventLog,
		MRTD:                     bundle.MRTD,
		RTMR0:                    bundle.RTMR0,
		RTMR1:                    bundle.RTMR1,
		RTMR2:                    bundle.RTMR2,
		RTMR3:                    bundle.RTMR3,
		ReportDataExpectedSHA256: signing.ReportDataHashFromSSHPublicKey(bundle.SSHPublicKey),
		PolicyVersion:            policyVersionOrDefault(bundle.PolicyVersion),
		IssuedAt:                 now,
		ExpiresAt:                req.ExpiresAt,
		Nonce:                    req.Nonce,
	}

	signed, err := h.signer.SignBundle(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "bundle_signing_failed")
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

func isRequestStatus(s access.Status) bool {
	switch s {
	case access.StatusPendingLocalConfirm,
		access.StatusApproved,
		access.StatusDeniedLocal,
		access.StatusRevoked,
		access.StatusExpired,
		access.StatusVerificationFailed,
		access.StatusConnected:
		return true
	default:
		return false
	}
}

// --- Install Session handlers ---

type createSessionBody struct {
	RequesterID string `json:"requester_id"`
	Source      string `json:"source"`
}

type createSessionResponse struct {
	Session      access.InstallSession `json:"session"`
	InstallToken string                `json:"install_token"`
	InstallURL   string                `json:"install_url"`
}

// CreateSession handles POST /v1/sessions.
func (h *Handlers) CreateSession(w http.ResponseWriter, r *http.Request) {
	var body createSessionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if body.RequesterID == "" {
		writeError(w, http.StatusBadRequest, "requester_id is required")
		return
	}

	session, rawToken := access.NewInstallSession(body.RequesterID, body.Source, defaultRequestTTL)
	if err := h.sessions.Create(r.Context(), session); err != nil {
		writeError(w, http.StatusInternalServerError, "create_failed")
		return
	}

	// Build install URL from the request host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	installURL := fmt.Sprintf("%s://%s/install?token=%s", scheme, r.Host, rawToken)

	_ = h.audit.Log(r.Context(), "install_session", session.ID, "created", body.RequesterID, "")
	writeJSON(w, http.StatusCreated, createSessionResponse{
		Session:      session,
		InstallToken: rawToken,
		InstallURL:   installURL,
	})
}

// GetSession handles GET /v1/sessions/{id}.
func (h *Handlers) GetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	session, err := h.sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}
	writeJSON(w, http.StatusOK, session)
}

type approveSessionBody struct {
	Approved bool `json:"approved"`
}

// ApproveSession handles POST /v1/sessions/{id}/approve.
func (h *Handlers) ApproveSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body approveSessionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	session, err := h.sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}

	if body.Approved {
		err = session.Approve()
	} else {
		err = session.Deny()
	}
	if err != nil {
		writeError(w, http.StatusConflict, "invalid_transition")
		return
	}

	if err := h.sessions.Update(r.Context(), session); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed")
		return
	}

	action := "denied"
	if body.Approved {
		action = "approved"
	}
	_ = h.audit.Log(r.Context(), "install_session", id, action, "", "")
	writeJSON(w, http.StatusOK, session)
}

type registerIdentityBody struct {
	ConnectorID string `json:"connector_id"`
	DeviceID    string `json:"device_id"`
}

// RegisterIdentity handles POST /v1/sessions/{id}/register.
func (h *Handlers) RegisterIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body registerIdentityBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	session, err := h.sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}

	if err := session.Register(body.ConnectorID, body.DeviceID); err != nil {
		if errors.Is(err, access.ErrInvalidTransition) {
			writeError(w, http.StatusConflict, "invalid_transition")
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if err := h.sessions.Update(r.Context(), session); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed")
		return
	}

	_ = h.audit.Log(r.Context(), "install_session", id, "registered", "", body.ConnectorID)
	writeJSON(w, http.StatusOK, session)
}

type sessionResultBody struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

// SessionResult handles POST /v1/sessions/{id}/result.
func (h *Handlers) SessionResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body sessionResultBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	session, err := h.sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}

	status := access.InstallStatus(body.Status)
	switch status {
	case access.InstallStatusInstalled:
		err = session.Complete()
	case access.InstallStatusFailed:
		err = session.Fail(body.ReasonCode)
	default:
		writeError(w, http.StatusBadRequest, "invalid status: must be installed or failed")
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, "invalid_transition")
		return
	}

	if err := h.sessions.Update(r.Context(), session); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed")
		return
	}

	_ = h.audit.Log(r.Context(), "install_session", id, "result:"+body.Status, "", body.ReasonCode)
	writeJSON(w, http.StatusOK, session)
}

type redeemTokenBody struct {
	TokenDigest string `json:"token_digest"`
}

// RedeemToken handles POST /v1/sessions/redeem.
func (h *Handlers) RedeemToken(w http.ResponseWriter, r *http.Request) {
	var body redeemTokenBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if body.TokenDigest == "" {
		writeError(w, http.StatusBadRequest, "token_digest is required")
		return
	}

	session, err := h.sessions.RedeemToken(r.Context(), body.TokenDigest)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "redeem_failed")
		return
	}

	_ = h.audit.Log(r.Context(), "install_session", session.ID, "redeemed", "", "")
	writeJSON(w, http.StatusOK, session)
}

// --- Device queries ---

// ListPending handles GET /v1/devices/{deviceID}/pending.
func (h *Handlers) ListPending(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceID")
	items, err := h.requests.ListPending(r.Context(), deviceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	if items == nil {
		items = []access.ConnectionRequest{}
	}
	writeJSON(w, http.StatusOK, items)
}

// ListAudit handles GET /v1/audit with optional filters and pagination.
func (h *Handlers) ListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 50
	offset := 0
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_offset")
			return
		}
		offset = n
	}

	var since *time.Time
	if raw := q.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since")
			return
		}
		since = &t
	}
	var until *time.Time
	if raw := q.Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_until")
			return
		}
		until = &t
	}

	items, err := h.audit.List(r.Context(), store.AuditListOptions{
		EntityType: q.Get("entity_type"),
		EntityID:   q.Get("entity_id"),
		Since:      since,
		Until:      until,
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	if items == nil {
		items = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, items)
}

// --- Signing keys ---

// SigningKeys handles GET /v1/signing-keys.
func (h *Handlers) SigningKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.signer.Keyset())
}

// --- Connector registration ---

type registerConnectorBody struct {
	ConnectorID   string `json:"connector_id"`
	SSHPublicKey  string `json:"ssh_public_key"`
	QuoteHex      string `json:"quote_hex"`
	EventLog      string `json:"event_log"`
	MRTD          string `json:"mrtd"`
	RTMR0         string `json:"rtmr0"`
	RTMR1         string `json:"rtmr1"`
	RTMR2         string `json:"rtmr2"`
	RTMR3         string `json:"rtmr3"`
	PolicyVersion string `json:"policy_version"`
	Info          string `json:"info"`
}

// RegisterConnector handles POST /v1/connectors/register.
func (h *Handlers) RegisterConnector(w http.ResponseWriter, r *http.Request) {
	var body registerConnectorBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if body.ConnectorID == "" || body.SSHPublicKey == "" {
		writeError(w, http.StatusBadRequest, "connector_id and ssh_public_key are required")
		return
	}

	bundle := store.ConnectorBundle{
		ConnectorID:   body.ConnectorID,
		SSHPublicKey:  body.SSHPublicKey,
		QuoteHex:      body.QuoteHex,
		EventLog:      body.EventLog,
		MRTD:          body.MRTD,
		RTMR0:         body.RTMR0,
		RTMR1:         body.RTMR1,
		RTMR2:         body.RTMR2,
		RTMR3:         body.RTMR3,
		PolicyVersion: body.PolicyVersion,
		Info:          body.Info,
	}
	if err := h.bundles.Register(r.Context(), bundle); err != nil {
		writeError(w, http.StatusInternalServerError, "register_failed")
		return
	}

	_ = h.audit.Log(r.Context(), "connector", body.ConnectorID, "registered", "", "")
	writeJSON(w, http.StatusCreated, map[string]string{"status": "registered", "connector_id": body.ConnectorID})
}

// ListConnectors handles GET /v1/connectors.
func (h *Handlers) ListConnectors(w http.ResponseWriter, r *http.Request) {
	items, err := h.bundles.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list_failed")
		return
	}
	if items == nil {
		items = []store.ConnectorBundle{}
	}
	writeJSON(w, http.StatusOK, items)
}

// GetConnector handles GET /v1/connectors/{id}.
func (h *Handlers) GetConnector(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := h.bundles.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, access.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get_failed")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// --- Operational endpoints ---

// Healthz handles GET /healthz.
func (h *Handlers) Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// InstallLanding handles GET /install.
func (h *Handlers) InstallLanding(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Enclout Connector Install</title></head>
<body>
<h1>Enclout Connector Install</h1>
<p>Use the install token provided to complete connector setup.</p>
</body>
</html>`))
}
