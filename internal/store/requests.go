package store

import (
	"context"
	"database/sql"
	"time"

	"enclout/internal/access"
)

type RequestRepository struct {
	db *sql.DB
}

func NewRequestRepository(db *sql.DB) *RequestRepository {
	return &RequestRepository{db: db}
}

func (r *RequestRepository) Create(ctx context.Context, req access.ConnectionRequest) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO connection_requests (id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.RequesterID, req.DeviceID, req.ConnectorID, req.Source,
		string(req.Status), req.Nonce, req.ReasonCode,
		req.CreatedAt.Format(time.RFC3339), req.ExpiresAt.Format(time.RFC3339), now,
	)
	return err
}

func (r *RequestRepository) Get(ctx context.Context, id string) (access.ConnectionRequest, error) {
	var req access.ConnectionRequest
	var status, createdAt, expiresAt string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at
		 FROM connection_requests WHERE id = ?`, id,
	).Scan(&req.ID, &req.RequesterID, &req.DeviceID, &req.ConnectorID, &req.Source,
		&status, &req.Nonce, &req.ReasonCode, &createdAt, &expiresAt,
	)
	if err == sql.ErrNoRows {
		return access.ConnectionRequest{}, access.ErrNotFound
	}
	if err != nil {
		return access.ConnectionRequest{}, err
	}
	req.Status = access.Status(status)
	req.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return req, nil
}

func (r *RequestRepository) Update(ctx context.Context, req access.ConnectionRequest) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx,
		`UPDATE connection_requests SET status = ?, reason_code = ?, updated_at = ? WHERE id = ?`,
		string(req.Status), req.ReasonCode, now, req.ID,
	)
	return err
}

func (r *RequestRepository) ListPending(ctx context.Context, deviceID string) ([]access.ConnectionRequest, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at
		 FROM connection_requests WHERE device_id = ? AND status = ?`,
		deviceID, string(access.StatusPendingLocalConfirm),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []access.ConnectionRequest
	for rows.Next() {
		var req access.ConnectionRequest
		var status, createdAt, expiresAt string
		if err := rows.Scan(&req.ID, &req.RequesterID, &req.DeviceID, &req.ConnectorID, &req.Source,
			&status, &req.Nonce, &req.ReasonCode, &createdAt, &expiresAt,
		); err != nil {
			return nil, err
		}
		req.Status = access.Status(status)
		req.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		req.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
		out = append(out, req)
	}
	return out, rows.Err()
}
