package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"enclout/services/local-agent/internal/api"
	"enclout/services/local-agent/internal/install"
)

const defaultLabel = "ai.enclout.agent"

type installRunnerFunc func(ctx context.Context, client install.InstallerAPI, installer install.ServiceInstaller, cfg install.Config) error

func main() {
	if err := run(context.Background(), os.Args[1:], os.LookupEnv); err != nil {
		log.Fatalf("install failed: %v", err)
	}
}

func run(ctx context.Context, args []string, lookupEnv func(string) (string, bool)) error {
	newInstaller, err := installerFactoryForGOOS(runtime.GOOS)
	if err != nil {
		return err
	}
	return runWithDeps(
		ctx,
		args,
		lookupEnv,
		runtime.GOOS,
		newInstaller,
		install.Run,
	)
}

func runWithDeps(
	ctx context.Context,
	args []string,
	lookupEnv func(string) (string, bool),
	goos string,
	newInstaller func() install.ServiceInstaller,
	runInstall installRunnerFunc,
) error {
	if goos != "darwin" && goos != "linux" {
		return fmt.Errorf("installer is only supported on darwin or linux, got %s", goos)
	}

	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	token := fs.String("token", "", "one-time install token")
	agentBin := fs.String("agent-bin", "", "path to local-agent binary")
	label := fs.String("label", defaultLabel, "service label")
	controlPlaneURL := fs.String("control-plane-url", envOrEmpty(lookupEnv, "CONTROL_PLANE_URL"), "control-plane base url")
	agentToken := fs.String("agent-token", envOrEmpty(lookupEnv, "AGENT_TOKEN"), "control-plane API bearer token")
	localUsername := fs.String("local-username", envOrEmpty(lookupEnv, "LOCAL_USERNAME"), "local account username")
	dcapVerifierURL := fs.String("dcap-verifier-url", envOrEmpty(lookupEnv, "DCAP_VERIFIER_URL"), "dcap verifier base url")
	connectorID := fs.String("connector-id", envOrEmpty(lookupEnv, "CONNECTOR_ID"), "connector id override")
	deviceID := fs.String("device-id", envOrEmpty(lookupEnv, "DEVICE_ID"), "device id override")
	servicePath := fs.String("service-path", "", "service file path")
	plistPath := fs.String("plist-path", "", "deprecated alias for -service-path")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*token) == "" {
		return errors.New("missing required -token")
	}
	if strings.TrimSpace(*agentBin) == "" {
		return errors.New("missing required -agent-bin")
	}
	if strings.TrimSpace(*controlPlaneURL) == "" {
		return errors.New("missing required CONTROL_PLANE_URL or -control-plane-url")
	}
	if strings.TrimSpace(*dcapVerifierURL) == "" {
		return errors.New("missing required DCAP_VERIFIER_URL or -dcap-verifier-url")
	}
	if strings.TrimSpace(*localUsername) == "" {
		u, err := user.Current()
		if err != nil || strings.TrimSpace(u.Username) == "" {
			return fmt.Errorf("resolve local username: %w", err)
		}
		*localUsername = u.Username
	}

	resolvedServicePath := strings.TrimSpace(*servicePath)
	if resolvedServicePath == "" {
		resolvedServicePath = strings.TrimSpace(*plistPath)
	}
	if resolvedServicePath == "" {
		home := envOrEmpty(lookupEnv, "HOME")
		if home == "" {
			return errors.New("missing HOME for default service path; set -service-path")
		}
		switch goos {
		case "darwin":
			resolvedServicePath = defaultPlistPath(home, *label)
		case "linux":
			resolvedServicePath = defaultSystemdUnitPath(home, *label)
		default:
			return fmt.Errorf("unsupported goos %s", goos)
		}
	}

	env := buildInstallEnv(*localUsername, *controlPlaneURL, *dcapVerifierURL, func(key string) string {
		return envOrEmpty(lookupEnv, key)
	})
	if v := strings.TrimSpace(*connectorID); v != "" {
		env["CONNECTOR_ID"] = v
	}
	if v := strings.TrimSpace(*deviceID); v != "" {
		env["DEVICE_ID"] = v
	}

	client := api.NewClient(*controlPlaneURL, *agentToken)
	installer := newInstaller()
	return runInstall(ctx, client, installer, install.Config{
		InstallToken:         *token,
		Label:                *label,
		AgentBinary:          *agentBin,
		PlistPath:            resolvedServicePath,
		InstallFailureReason: installFailureReasonForGOOS(goos),
		Env:                  env,
	})
}

func defaultPlistPath(home string, label string) string {
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist")
}

func defaultSystemdUnitPath(home string, label string) string {
	if !strings.HasSuffix(label, ".service") {
		label += ".service"
	}
	return filepath.Join(home, ".config", "systemd", "user", label)
}

func buildInstallEnv(localUsername string, controlPlaneURL string, dcapVerifierURL string, getenv func(string) string) map[string]string {
	out := map[string]string{
		"CONTROL_PLANE_URL": controlPlaneURL,
		"LOCAL_USERNAME":    localUsername,
		"DCAP_VERIFIER_URL": dcapVerifierURL,
	}

	for _, key := range []string{
		"AGENT_TOKEN",
		"DCAP_VERIFIER_TOKEN",
		"DCAP_VERIFIER_TIMEOUT",
		"MANAGED_KEYS_DIR",
		"ALLOW_MRTD",
		"ALLOW_RTMR3",
		"CONNECTOR_ID",
		"DEVICE_ID",
		"CONTROL_PLANE_SIGNING_KEYS_JSON",
		"CONTROL_PLANE_SIGNING_PUBKEY_B64",
		"CONTROL_PLANE_SIGNING_KID",
		"SIGNING_KEYSET_CACHE_TTL",
	} {
		v := strings.TrimSpace(getenv(key))
		if v != "" {
			out[key] = v
		}
	}
	return out
}

func envOrEmpty(lookupEnv func(string) (string, bool), key string) string {
	if v, ok := lookupEnv(key); ok {
		return v
	}
	return ""
}

func installerFactoryForGOOS(goos string) (func() install.ServiceInstaller, error) {
	switch goos {
	case "darwin":
		return func() install.ServiceInstaller { return install.NewLaunchdInstaller() }, nil
	case "linux":
		return func() install.ServiceInstaller { return install.NewSystemdInstaller() }, nil
	default:
		return nil, fmt.Errorf("installer is only supported on darwin or linux, got %s", goos)
	}
}

func installFailureReasonForGOOS(goos string) string {
	switch goos {
	case "linux":
		return install.InstallFailureSystemd
	default:
		return install.InstallFailureLaunchd
	}
}
