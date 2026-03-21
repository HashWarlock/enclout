package server

import "net/http"

// NewRouter builds the HTTP mux using Go 1.22+ method-prefixed patterns.
func NewRouter(h *Handlers, auth func(http.Handler) http.Handler) http.Handler {
	mux := http.NewServeMux()

	// Connection requests
	mux.Handle("POST /v1/requests", auth(http.HandlerFunc(h.CreateRequest)))
	mux.Handle("GET /v1/requests/{id}", auth(http.HandlerFunc(h.GetRequest)))
	mux.Handle("POST /v1/requests/{id}/decision", auth(http.HandlerFunc(h.PostDecision)))
	mux.Handle("POST /v1/requests/{id}/result", auth(http.HandlerFunc(h.PostResult)))
	mux.Handle("GET /v1/requests/{id}/bundle", auth(http.HandlerFunc(h.GetBundle)))

	// Install sessions
	mux.Handle("POST /v1/sessions", auth(http.HandlerFunc(h.CreateSession)))
	mux.Handle("GET /v1/sessions/{id}", auth(http.HandlerFunc(h.GetSession)))
	mux.Handle("POST /v1/sessions/{id}/approve", auth(http.HandlerFunc(h.ApproveSession)))
	mux.Handle("POST /v1/sessions/{id}/register", auth(http.HandlerFunc(h.RegisterIdentity)))
	mux.Handle("POST /v1/sessions/{id}/result", auth(http.HandlerFunc(h.SessionResult)))
	mux.Handle("POST /v1/sessions/redeem", auth(http.HandlerFunc(h.RedeemToken)))

	// Device queries
	mux.Handle("GET /v1/devices/{deviceID}/pending", auth(http.HandlerFunc(h.ListPending)))

	// Signing keys + connector registration
	mux.Handle("GET /v1/signing-keys", auth(http.HandlerFunc(h.SigningKeys)))
	mux.Handle("POST /v1/connectors/register", auth(http.HandlerFunc(h.RegisterConnector)))

	// Operational (no auth)
	mux.Handle("GET /install", http.HandlerFunc(h.InstallLanding))
	mux.Handle("GET /healthz", http.HandlerFunc(h.Healthz))

	return mux
}
