package store

import (
	"context"
	"database/sql"
	"time"

	"enclout/internal/access"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, session access.InstallSession) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO install_sessions (id, requester_id, device_id, connector_id, source, status, token_digest, reason_code, created_at, expires_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.RequesterID, session.DeviceID, session.ConnectorID, session.Source,
		string(session.Status), session.TokenDigest, session.ReasonCode,
		session.CreatedAt.Format(time.RFC3339), session.ExpiresAt.Format(time.RFC3339), now,
	)
	return err
}

func (r *SessionRepository) Get(ctx context.Context, id string) (access.InstallSession, error) {
	var s access.InstallSession
	var status, createdAt, expiresAt string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, requester_id, device_id, connector_id, source, status, token_digest, reason_code, created_at, expires_at
		 FROM install_sessions WHERE id = ?`, id,
	).Scan(&s.ID, &s.RequesterID, &s.DeviceID, &s.ConnectorID, &s.Source,
		&status, &s.TokenDigest, &s.ReasonCode, &createdAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return access.InstallSession{}, access.ErrNotFound
	}
	if err != nil {
		return access.InstallSession{}, err
	}
	s.Status = access.InstallStatus(status)
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return s, nil
}

func (r *SessionRepository) Update(ctx context.Context, session access.InstallSession) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx,
		`UPDATE install_sessions SET status = ?, device_id = ?, connector_id = ?, token_digest = ?, reason_code = ?, updated_at = ? WHERE id = ?`,
		string(session.Status), session.DeviceID, session.ConnectorID, session.TokenDigest, session.ReasonCode, now, session.ID,
	)
	return err
}

// RedeemToken looks up a session by token digest, clears the digest atomically,
// and returns the session. Second redemption of the same token returns ErrNotFound.
func (r *SessionRepository) RedeemToken(ctx context.Context, tokenDigest string) (access.InstallSession, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return access.InstallSession{}, err
	}
	defer tx.Rollback()

	var s access.InstallSession
	var status, createdAt, expiresAt string
	err = tx.QueryRowContext(ctx,
		`SELECT id, requester_id, device_id, connector_id, source, status, token_digest, reason_code, created_at, expires_at
		 FROM install_sessions WHERE token_digest = ? AND token_digest != ''`, tokenDigest,
	).Scan(&s.ID, &s.RequesterID, &s.DeviceID, &s.ConnectorID, &s.Source,
		&status, &s.TokenDigest, &s.ReasonCode, &createdAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return access.InstallSession{}, access.ErrNotFound
	}
	if err != nil {
		return access.InstallSession{}, err
	}
	s.Status = access.InstallStatus(status)
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)

	// Clear the token digest so it can't be redeemed again
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = tx.ExecContext(ctx,
		`UPDATE install_sessions SET token_digest = '', updated_at = ? WHERE id = ?`,
		now, s.ID,
	)
	if err != nil {
		return access.InstallSession{}, err
	}

	if err := tx.Commit(); err != nil {
		return access.InstallSession{}, err
	}
	s.TokenDigest = ""
	return s, nil
}
