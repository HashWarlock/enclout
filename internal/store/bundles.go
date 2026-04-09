package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"enclout/internal/access"
)

type ConnectorBundle struct {
	ConnectorID   string
	SSHPublicKey  string
	QuoteHex      string
	EventLog      string
	MRTD          string
	RTMR0         string
	RTMR1         string
	RTMR2         string
	RTMR3         string
	PolicyVersion string
	Info          string
	RegisteredAt  time.Time
}

type BundleRepository struct {
	db *sql.DB
}

func NewBundleRepository(db *sql.DB) *BundleRepository {
	return &BundleRepository{db: db}
}

func (r *BundleRepository) Register(ctx context.Context, b ConnectorBundle) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := r.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO connector_bundles
		 (connector_id, ssh_public_key, quote_hex, event_log, mrtd, rtmr0, rtmr1, rtmr2, rtmr3, policy_version, info, registered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ConnectorID, b.SSHPublicKey, b.QuoteHex, b.EventLog,
		b.MRTD, b.RTMR0, b.RTMR1, b.RTMR2, b.RTMR3,
		b.PolicyVersion, b.Info, now,
	)
	return err
}

func (r *BundleRepository) Get(ctx context.Context, connectorID string) (ConnectorBundle, error) {
	var b ConnectorBundle
	var registeredAt string
	err := r.db.QueryRowContext(ctx,
		`SELECT connector_id, ssh_public_key, quote_hex, event_log, mrtd, rtmr0, rtmr1, rtmr2, rtmr3, policy_version, info, registered_at
		 FROM connector_bundles WHERE connector_id = ?`, connectorID,
	).Scan(&b.ConnectorID, &b.SSHPublicKey, &b.QuoteHex, &b.EventLog,
		&b.MRTD, &b.RTMR0, &b.RTMR1, &b.RTMR2, &b.RTMR3,
		&b.PolicyVersion, &b.Info, &registeredAt,
	)
	if err == sql.ErrNoRows {
		return ConnectorBundle{}, fmt.Errorf("connector %q: %w", connectorID, access.ErrNotFound)
	}
	if err != nil {
		return ConnectorBundle{}, err
	}
	b.RegisteredAt, _ = time.Parse(time.RFC3339, registeredAt)
	return b, nil
}

func (r *BundleRepository) List(ctx context.Context) ([]ConnectorBundle, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT connector_id, ssh_public_key, quote_hex, event_log, mrtd, rtmr0, rtmr1, rtmr2, rtmr3, policy_version, info, registered_at
		 FROM connector_bundles ORDER BY connector_id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ConnectorBundle
	for rows.Next() {
		var b ConnectorBundle
		var registeredAt string
		if err := rows.Scan(&b.ConnectorID, &b.SSHPublicKey, &b.QuoteHex, &b.EventLog,
			&b.MRTD, &b.RTMR0, &b.RTMR1, &b.RTMR2, &b.RTMR3,
			&b.PolicyVersion, &b.Info, &registeredAt,
		); err != nil {
			return nil, err
		}
		b.RegisteredAt, _ = time.Parse(time.RFC3339, registeredAt)
		out = append(out, b)
	}
	return out, rows.Err()
}
