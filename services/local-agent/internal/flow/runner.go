package flow

import (
	"context"
	"errors"
	"fmt"

	"enclout/services/local-agent/internal/api"
	"enclout/services/local-agent/internal/approval"
	"enclout/services/local-agent/internal/verify"
)

var ErrUserDenied = errors.New("user denied local approval")

type API interface {
	PostLocalDecision(ctx context.Context, requestID string, approved bool) error
	GetAttestationBundle(ctx context.Context, requestID string) (api.Bundle, error)
	PostResult(ctx context.Context, requestID string, status string, reasonCode string) error
}

type Prompter interface {
	Confirm(ctx context.Context, req approval.RequestSummary) (bool, error)
}

type Verifier interface {
	Verify(ctx context.Context, bundle verify.Bundle) (verify.Decision, error)
}

type KeyInstaller interface {
	Install(username string, pubKey string) error
}

type Request struct {
	ID          string
	ConnectorID string
	LocalUser   string
}

type Runner struct {
	api                        API
	prompter                   Prompter
	verifier                   Verifier
	keys                       KeyInstaller
	controlPlaneSigningKeysB64 map[string]string
}

func NewRunner(apiClient API, prompter Prompter, verifier Verifier, keys KeyInstaller, controlPlaneSigningKeysB64 map[string]string) Runner {
	keysetCopy := make(map[string]string, len(controlPlaneSigningKeysB64))
	for kid, key := range controlPlaneSigningKeysB64 {
		keysetCopy[kid] = key
	}
	return Runner{
		api:                        apiClient,
		prompter:                   prompter,
		verifier:                   verifier,
		keys:                       keys,
		controlPlaneSigningKeysB64: keysetCopy,
	}
}

func (r Runner) Process(ctx context.Context, req Request) error {
	approved, err := r.prompter.Confirm(ctx, approval.RequestSummary{
		ID:          req.ID,
		ConnectorID: req.ConnectorID,
	})
	if err != nil {
		return err
	}

	if err := r.api.PostLocalDecision(ctx, req.ID, approved); err != nil {
		return err
	}
	if !approved {
		return ErrUserDenied
	}

	signedBundle, err := r.api.GetAttestationBundle(ctx, req.ID)
	if err != nil {
		return err
	}

	if err := verify.VerifySignedBundleWithKeyset(
		signedBundle.PayloadRaw,
		signedBundle.Signature,
		signedBundle.Alg,
		signedBundle.KID,
		r.controlPlaneSigningKeysB64,
	); err != nil {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", verify.ReasonBundleInvalid)
		return err
	}

	bundle, err := parseBundlePayload(signedBundle.Payload)
	if err != nil {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", verify.ReasonBundleInvalid)
		return err
	}

	decision, err := r.verifier.Verify(ctx, bundle)
	if err != nil {
		reasonCode := verify.ReasonQuoteInvalid
		var verr verify.VerificationError
		if errors.As(err, &verr) {
			reasonCode = verr.Code
		}
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", reasonCode)
		return err
	}
	if !decision.Trusted {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", decision.ReasonCode)
		return fmt.Errorf("untrusted decision: %s", decision.ReasonCode)
	}

	if err := r.keys.Install(req.LocalUser, bundle.SSHPublicKey); err != nil {
		_ = r.api.PostResult(ctx, req.ID, "verification_failed", "TransportFailure")
		return err
	}

	return r.api.PostResult(ctx, req.ID, "connected", "")
}

func parseBundlePayload(payload map[string]any) (verify.Bundle, error) {
	out := verify.Bundle{
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
		return verify.Bundle{}, fmt.Errorf("bundle payload missing required fields")
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
