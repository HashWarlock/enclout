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

func main() {
	if err := run(context.Background(), os.Args[1:], os.LookupEnv); err != nil {
		log.Fatalf("install failed: %v", err)
	}
}

func run(ctx context.Context, args []string, lookupEnv func(string) (string, bool)) error {
	if runtime.GOOS != "darwin" {
		return errors.New("launchd installer is only supported on darwin")
	}

	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	token := fs.String("token", "", "one-time install token")
	agentBin := fs.String("agent-bin", "", "path to local-agent binary")
	label := fs.String("label", defaultLabel, "launchd label")
	controlPlaneURL := fs.String("control-plane-url", envOrEmpty(lookupEnv, "CONTROL_PLANE_URL"), "control-plane base url")
	agentToken := fs.String("agent-token", envOrEmpty(lookupEnv, "AGENT_TOKEN"), "control-plane API bearer token")
	localUsername := fs.String("local-username", envOrEmpty(lookupEnv, "LOCAL_USERNAME"), "local account username")
	dcapVerifierURL := fs.String("dcap-verifier-url", envOrEmpty(lookupEnv, "DCAP_VERIFIER_URL"), "dcap verifier base url")
	plistPath := fs.String("plist-path", "", "launch agent plist path")
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

	if strings.TrimSpace(*plistPath) == "" {
		home := envOrEmpty(lookupEnv, "HOME")
		if home == "" {
			return errors.New("missing HOME for default plist path; set -plist-path")
		}
		*plistPath = defaultPlistPath(home, *label)
	}

	env := buildInstallEnv(*localUsername, *controlPlaneURL, *dcapVerifierURL, func(key string) string {
		return envOrEmpty(lookupEnv, key)
	})

	client := api.NewClient(*controlPlaneURL, *agentToken)
	installer := install.NewLaunchdInstaller()
	return install.Run(ctx, client, installer, install.Config{
		InstallToken: *token,
		Label:        *label,
		AgentBinary:  *agentBin,
		PlistPath:    *plistPath,
		Env:          env,
	})
}

func defaultPlistPath(home string, label string) string {
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist")
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
