package server

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"enclout/internal/signing"
	"enclout/internal/store"
)

// Server wraps an HTTP server with all dependencies.
type Server struct {
	httpServer *http.Server
	db         *sql.DB
	logger     *slog.Logger
}

// Config holds server configuration.
type Config struct {
	Bind      string
	AuthToken string
	Logger    *slog.Logger
}

// Deps holds all service dependencies for the HTTP handlers.
type Deps struct {
	DB       *sql.DB
	Requests *store.RequestRepository
	Sessions *store.SessionRepository
	Bundles  *store.BundleRepository
	Audit    *store.AuditLogger
	Signer   signing.BundleSigner
}

// New creates a new Server with middleware and routing.
func New(cfg Config, deps Deps) *Server {
	h := NewHandlers(deps)
	auth := func(next http.Handler) http.Handler {
		return BearerAuth(cfg.AuthToken, next)
	}
	router := NewRouter(h, auth)
	handler := RequestID(RequestLogger(cfg.Logger, router))
	return &Server{
		httpServer: &http.Server{Addr: cfg.Bind, Handler: handler},
		db:         deps.DB,
		logger:     cfg.Logger,
	}
}

// Start begins listening and serving HTTP. Blocks until the server is closed.
func (s *Server) Start() error { return s.httpServer.ListenAndServe() }

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// StartExpiration runs a background goroutine that expires stale connection
// requests and install sessions every 30 seconds.
func (s *Server) StartExpiration(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC().Format(time.RFC3339)
				_, err := s.db.ExecContext(ctx,
					`UPDATE connection_requests SET status = 'expired', updated_at = ? WHERE expires_at < ? AND status IN ('pending_local_confirm', 'approved')`,
					now, now,
				)
				if err != nil {
					s.logger.Warn("expire connection requests", "error", err)
				}
				_, err = s.db.ExecContext(ctx,
					`UPDATE install_sessions SET status = 'failed', reason_code = 'Expired', updated_at = ? WHERE expires_at < ? AND status IN ('requested', 'approved')`,
					now, now,
				)
				if err != nil {
					s.logger.Warn("expire install sessions", "error", err)
				}
			}
		}
	}()
}
