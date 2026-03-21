package agent

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"
)

// PendingPoller retrieves pending connection requests for a device.
type PendingPoller interface {
	ListPending(ctx context.Context, deviceID string) ([]PendingRequest, error)
}

// PendingRequest is a minimal representation of a pending request from the server.
type PendingRequest struct {
	ID          string
	ConnectorID string
	LocalUser   string
}

// Daemon polls the server for pending connection requests and processes them.
type Daemon struct {
	poller       PendingPoller
	runner       *Runner
	deviceID     string
	baseInterval time.Duration
	logger       *slog.Logger
}

// NewDaemon creates a Daemon that polls at the given interval.
func NewDaemon(poller PendingPoller, runner *Runner, deviceID string, baseInterval time.Duration, logger *slog.Logger) *Daemon {
	if logger == nil {
		logger = slog.Default()
	}
	if baseInterval <= 0 {
		baseInterval = 10 * time.Second
	}
	return &Daemon{
		poller:       poller,
		runner:       runner,
		deviceID:     deviceID,
		baseInterval: baseInterval,
		logger:       logger,
	}
}

// Run starts the poll loop. It blocks until ctx is cancelled and returns nil on
// graceful shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	d.logger.Info("agent daemon started", "device_id", d.deviceID, "interval", d.baseInterval)

	backoff := d.baseInterval
	const maxBackoff = 60 * time.Second

	for {
		interval := jitter(backoff)
		select {
		case <-ctx.Done():
			d.logger.Info("agent daemon shutting down")
			return nil
		case <-time.After(interval):
		}

		requests, err := d.poller.ListPending(ctx, d.deviceID)
		if err != nil {
			if ctx.Err() != nil {
				d.logger.Info("agent daemon shutting down")
				return nil
			}
			d.logger.Error("poll failed", "error", err)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Reset backoff on successful poll.
		backoff = d.baseInterval

		for _, pr := range requests {
			if ctx.Err() != nil {
				d.logger.Info("agent daemon shutting down")
				return nil
			}

			req := Request{
				ID:          pr.ID,
				ConnectorID: pr.ConnectorID,
				LocalUser:   pr.LocalUser,
			}
			if err := d.runner.Process(ctx, req); err != nil {
				d.logger.Error("request processing failed",
					"request_id", req.ID,
					"error", err,
				)
			}
		}
	}
}

// jitter applies a +/-20% random jitter to the given duration.
func jitter(d time.Duration) time.Duration {
	factor := 0.8 + rand.Float64()*0.4 // [0.8, 1.2)
	return time.Duration(float64(d) * factor)
}
