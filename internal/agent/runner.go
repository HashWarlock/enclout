package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"enclout/internal/attestation"
	"enclout/internal/signing"
)

// ErrUserDenied is returned when the user denies local approval.
var ErrUserDenied = errors.New("user denied local approval")

const auditSinkNotReadyReason = "AuditSinkNotReady"

// SignedBundle is the server's response containing a signed attestation bundle.
// PayloadRaw is the exact bytes that were signed; Payload is the parsed map.
type SignedBundle struct {
	Payload    map[string]any
	PayloadRaw []byte
	Signature  string
	Alg        string
	KID        string
}

// RequestClient is the subset of the HTTP client used by the Runner.
type RequestClient interface {
	PostDecision(ctx context.Context, requestID string, approved bool) error
	GetBundle(ctx context.Context, requestID string) (SignedBundle, error)
	PostResult(ctx context.Context, requestID string, status string, reasonCode string) error
}

// BundleVerifier verifies an attestation bundle (DCAP + measurements).
type BundleVerifier interface {
	Verify(ctx context.Context, bundle attestation.Bundle) (attestation.Decision, error)
}

// KeyInstaller installs SSH public keys on the local system.
type KeyInstaller interface {
	Install(username string, pubKey string) error
}

// TrustedKeySource provides the current set of trusted signing keys.
type TrustedKeySource interface {
	TrustedKeys(ctx context.Context) (map[string]string, error)
}

// AuditSink reports whether audit logging is ready to accept new events.
type AuditSink interface {
	Ready(ctx context.Context) error
}

type noopAuditSink struct{}

func (noopAuditSink) Ready(context.Context) error { return nil }

// Request describes a pending connection request to be processed.
type Request struct {
	ID          string
	ConnectorID string
	LocalUser   string
}

// Runner processes individual connection requests through the full approval,
// verification, and key installation flow.
type Runner struct {
	client       RequestClient
	prompter     DecisionSource
	verifier     BundleVerifier
	keyInstaller KeyInstaller
	trustedKeys  TrustedKeySource
	auditSink    AuditSink
	installUser  string
	logger       *slog.Logger
}

// NewRunner creates a Runner with all required dependencies.
func NewRunner(
	client RequestClient,
	prompter DecisionSource,
	verifier BundleVerifier,
	keyInstaller KeyInstaller,
	trustedKeys TrustedKeySource,
	logger *slog.Logger,
) *Runner {
	return newRunner(client, prompter, verifier, keyInstaller, trustedKeys, "", noopAuditSink{}, logger)
}

// NewRunnerWithUsername creates a Runner that always installs keys for the
// configured local username, regardless of request payload contents.
func NewRunnerWithUsername(
	client RequestClient,
	prompter DecisionSource,
	verifier BundleVerifier,
	keyInstaller KeyInstaller,
	trustedKeys TrustedKeySource,
	username string,
	logger *slog.Logger,
) *Runner {
	return newRunner(client, prompter, verifier, keyInstaller, trustedKeys, username, noopAuditSink{}, logger)
}

// NewRunnerWithAuditSink creates a Runner that checks the audit sink health
// gate before reporting a connected result.
func NewRunnerWithAuditSink(
	client RequestClient,
	prompter DecisionSource,
	verifier BundleVerifier,
	keyInstaller KeyInstaller,
	trustedKeys TrustedKeySource,
	auditSink AuditSink,
	logger *slog.Logger,
) *Runner {
	return newRunner(client, prompter, verifier, keyInstaller, trustedKeys, "", auditSink, logger)
}

// NewRunnerWithUsernameAndAuditSink creates a Runner that installs keys for a
// fixed username and checks the audit sink health gate before connecting.
func NewRunnerWithUsernameAndAuditSink(
	client RequestClient,
	prompter DecisionSource,
	verifier BundleVerifier,
	keyInstaller KeyInstaller,
	trustedKeys TrustedKeySource,
	username string,
	auditSink AuditSink,
	logger *slog.Logger,
) *Runner {
	return newRunner(client, prompter, verifier, keyInstaller, trustedKeys, username, auditSink, logger)
}

func newRunner(
	client RequestClient,
	prompter DecisionSource,
	verifier BundleVerifier,
	keyInstaller KeyInstaller,
	trustedKeys TrustedKeySource,
	username string,
	auditSink AuditSink,
	logger *slog.Logger,
) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	if auditSink == nil {
		auditSink = noopAuditSink{}
	}
	return &Runner{
		client:       client,
		prompter:     prompter,
		verifier:     verifier,
		keyInstaller: keyInstaller,
		trustedKeys:  trustedKeys,
		auditSink:    auditSink,
		installUser:  username,
		logger:       logger,
	}
}

// Process handles a single connection request through the full flow:
// prompt -> decision -> bundle fetch -> signature verify -> attestation verify -> key install -> result.
func (r *Runner) Process(ctx context.Context, req Request) error {
	approved, err := r.prompter.Confirm(ctx, RequestSummary{
		ID:          req.ID,
		ConnectorID: req.ConnectorID,
	})
	if err != nil {
		return err
	}

	if err := r.client.PostDecision(ctx, req.ID, approved); err != nil {
		return err
	}
	if !approved {
		return ErrUserDenied
	}

	signedBundle, err := r.client.GetBundle(ctx, req.ID)
	if err != nil {
		return err
	}

	if r.trustedKeys == nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", attestation.ReasonBundleInvalid)
		return fmt.Errorf("trusted signing key source is not configured")
	}
	trustedKeys, err := r.trustedKeys.TrustedKeys(ctx)
	if err != nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", attestation.ReasonBundleInvalid)
		return err
	}

	if err := signing.VerifySignedBundleWithKeyset(
		signedBundle.PayloadRaw,
		signedBundle.Signature,
		signedBundle.Alg,
		signedBundle.KID,
		trustedKeys,
	); err != nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", attestation.ReasonBundleInvalid)
		return err
	}

	bundle, err := parseBundlePayload(signedBundle.Payload)
	if err != nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", attestation.ReasonBundleInvalid)
		return err
	}

	decision, err := r.verifier.Verify(ctx, bundle)
	if err != nil {
		reasonCode := attestation.ReasonQuoteInvalid
		var verr attestation.VerificationError
		if errors.As(err, &verr) {
			reasonCode = verr.Code
		}
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", reasonCode)
		return err
	}
	if !decision.Trusted {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", decision.ReasonCode)
		return fmt.Errorf("untrusted decision: %s", decision.ReasonCode)
	}

	username := r.installUser
	if username == "" {
		username = req.LocalUser
	}
	if err := r.auditSink.Ready(ctx); err != nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", auditSinkNotReadyReason)
		return fmt.Errorf("audit sink readiness check failed: %w", err)
	}

	if err := r.keyInstaller.Install(username, bundle.SSHPublicKey); err != nil {
		_ = r.client.PostResult(ctx, req.ID, "verification_failed", "TransportFailure")
		return err
	}

	return r.client.PostResult(ctx, req.ID, "connected", "")
}

func parseBundlePayload(payload map[string]any) (attestation.Bundle, error) {
	out := attestation.Bundle{
		ConnectorID:              stringField(payload, "connector_id"),
		SSHPublicKey:             stringField(payload, "ssh_public_key"),
		QuoteHex:                 stringField(payload, "quote_hex"),
		MRTD:                     stringField(payload, "mrtd"),
		RTMR0:                    stringField(payload, "rtmr0"),
		RTMR1:                    stringField(payload, "rtmr1"),
		RTMR2:                    stringField(payload, "rtmr2"),
		RTMR3:                    stringField(payload, "rtmr3"),
		ReportDataExpectedSHA256: stringField(payload, "report_data_expected_sha256"),
		PolicyVersion:            stringField(payload, "policy_version"),
	}

	if out.SSHPublicKey == "" || out.QuoteHex == "" {
		return attestation.Bundle{}, fmt.Errorf("bundle payload missing required fields")
	}
	return out, nil
}

func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
