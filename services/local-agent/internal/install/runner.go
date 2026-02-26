package install

import (
	"context"
	"fmt"
	"strings"

	"enclout/services/local-agent/internal/api"
)

const (
	InstallStatusInstalled = "installed"
	InstallStatusFailed    = "failed"

	InstallFailureInvalidConfig = "InvalidConfig"
	InstallFailureLaunchd       = "LaunchdInstallError"
)

type InstallerAPI interface {
	RedeemInstallToken(ctx context.Context, token string) (api.InstallSession, error)
	PostInstallResult(ctx context.Context, sessionID string, status string, reasonCode string) error
}

type ServiceConfig struct {
	Label       string
	AgentBinary string
	PlistPath   string
	Env         map[string]string
}

type ServiceInstaller interface {
	InstallAndStart(ctx context.Context, cfg ServiceConfig) error
}

type Config struct {
	InstallToken string
	Label        string
	AgentBinary  string
	PlistPath    string
	Env          map[string]string
}

func Run(ctx context.Context, client InstallerAPI, installer ServiceInstaller, cfg Config) error {
	session, err := client.RedeemInstallToken(ctx, cfg.InstallToken)
	if err != nil {
		return err
	}

	env := copyEnv(cfg.Env)
	if strings.TrimSpace(env["DEVICE_ID"]) == "" {
		env["DEVICE_ID"] = session.DeviceID
	}

	if err := validateConfig(cfg, env); err != nil {
		return failInstall(ctx, client, session.ID, InstallFailureInvalidConfig, err)
	}

	serviceCfg := ServiceConfig{
		Label:       cfg.Label,
		AgentBinary: cfg.AgentBinary,
		PlistPath:   cfg.PlistPath,
		Env:         env,
	}

	if err := installer.InstallAndStart(ctx, serviceCfg); err != nil {
		return failInstall(ctx, client, session.ID, InstallFailureLaunchd, err)
	}

	return client.PostInstallResult(ctx, session.ID, InstallStatusInstalled, "")
}

func validateConfig(cfg Config, env map[string]string) error {
	if strings.TrimSpace(cfg.Label) == "" {
		return fmt.Errorf("missing launchd label")
	}
	if strings.TrimSpace(cfg.AgentBinary) == "" {
		return fmt.Errorf("missing agent binary")
	}
	if strings.TrimSpace(cfg.PlistPath) == "" {
		return fmt.Errorf("missing plist path")
	}
	for _, key := range []string{"CONTROL_PLANE_URL", "DEVICE_ID", "LOCAL_USERNAME", "DCAP_VERIFIER_URL"} {
		if strings.TrimSpace(env[key]) == "" {
			return fmt.Errorf("missing %s", key)
		}
	}
	return nil
}

func copyEnv(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func failInstall(ctx context.Context, client InstallerAPI, sessionID string, reason string, cause error) error {
	postErr := client.PostInstallResult(ctx, sessionID, InstallStatusFailed, reason)
	if postErr == nil {
		return cause
	}
	return fmt.Errorf("%w (also failed to post install result: %v)", cause, postErr)
}
