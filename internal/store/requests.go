package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"enclout/internal/access"
)

type RequestRepository struct {
	db *sql.DB
}

type RequestListOptions struct {
	DeviceID    string
	RequesterID string
	Status      access.Status
	Limit       int
	Offset      int
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

// Transition atomically changes request status when the current status is in
// allowedFrom. It prevents stale read/modify/write races between concurrent
// transitions (for example result vs revoke).
func (r *RequestRepository) Transition(
	ctx context.Context,
	id string,
	allowedFrom []access.Status,
	to access.Status,
	reasonCode string,
) (access.ConnectionRequest, error) {
	if len(allowedFrom) == 0 {
		return access.ConnectionRequest{}, access.ErrInvalidTransition
	}

	placeholders := make([]string, len(allowedFrom))
	args := make([]any, 0, 4+len(allowedFrom))
	for i, st := range allowedFrom {
		placeholders[i] = "?"
		args = append(args, string(st))
	}

	now := time.Now().UTC().Format(time.RFC3339)
	query := fmt.Sprintf(
		`UPDATE connection_requests
		 SET status = ?, reason_code = ?, updated_at = ?
		 WHERE id = ? AND status IN (%s)`,
		strings.Join(placeholders, ","),
	)
	execArgs := []any{string(to), reasonCode, now, id}
	execArgs = append(execArgs, args...)

	res, err := r.db.ExecContext(ctx, query, execArgs...)
	if err != nil {
		return access.ConnectionRequest{}, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return access.ConnectionRequest{}, err
	}
	if rows > 0 {
		return r.Get(ctx, id)
	}

	if _, err := r.Get(ctx, id); err != nil {
		return access.ConnectionRequest{}, err
	}
	return access.ConnectionRequest{}, access.ErrInvalidTransition
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

func (r *RequestRepository) List(ctx context.Context, opts RequestListOptions) ([]access.ConnectionRequest, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	query := `SELECT id, requester_id, device_id, connector_id, source, status, nonce, reason_code, created_at, expires_at
		FROM connection_requests`
	var where []string
	var args []any
	if opts.DeviceID != "" {
		where = append(where, "device_id = ?")
		args = append(args, opts.DeviceID)
	}
	if opts.RequesterID != "" {
		where = append(where, "requester_id = ?")
		args = append(args, opts.RequesterID)
	}
	if opts.Status != "" {
		where = append(where, "status = ?")
		args = append(args, string(opts.Status))
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
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
