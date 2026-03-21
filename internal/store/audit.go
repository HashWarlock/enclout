package store

import (
	"context"
	"database/sql"
	"time"
)

type AuditEntry struct {
	ID         int64
	EntityType string
	EntityID   string
	Action     string
	Actor      string
	Detail     string
	CreatedAt  time.Time
}

type AuditLogger struct {
	db *sql.DB
}

func NewAuditLogger(db *sql.DB) *AuditLogger {
	return &AuditLogger{db: db}
}

func (a *AuditLogger) Log(ctx context.Context, entityType, entityID, action, actor, detail string) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO audit_log (entity_type, entity_id, action, actor, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		entityType, entityID, action, actor, detail, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (a *AuditLogger) QueryByEntity(ctx context.Context, entityType, entityID string) ([]AuditEntry, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, entity_type, entity_id, action, actor, detail, created_at
		 FROM audit_log WHERE entity_type = ? AND entity_id = ? ORDER BY id`,
		entityType, entityID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var createdAt string
		if err := rows.Scan(&e.ID, &e.EntityType, &e.EntityID, &e.Action, &e.Actor, &e.Detail, &createdAt); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, e)
	}
	return out, rows.Err()
}
