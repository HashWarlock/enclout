package install

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type systemdInstaller struct {
	runner commandRunner
}

func NewSystemdInstaller() ServiceInstaller {
	return newSystemdInstaller(osCommandRunner{})
}

func newSystemdInstaller(runner commandRunner) *systemdInstaller {
	return &systemdInstaller{runner: runner}
}

func (i *systemdInstaller) InstallAndStart(ctx context.Context, cfg ServiceConfig) error {
	unitPath := strings.TrimSpace(cfg.PlistPath)
	if unitPath == "" {
		return fmt.Errorf("missing systemd unit path")
	}

	unitData := renderSystemdUnit(cfg)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(unitPath, unitData, 0o644); err != nil {
		return err
	}

	unitName := filepath.Base(unitPath)
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	if err := i.runner.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err := i.runner.Run(ctx, "systemctl", "--user", "enable", "--now", unitName); err != nil {
		return err
	}
	return nil
}

func renderSystemdUnit(cfg ServiceConfig) []byte {
	var b bytes.Buffer
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Enclout Local Agent\n")
	b.WriteString("After=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + cfg.AgentBinary + "\n")
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=2\n")
	if len(cfg.Env) > 0 {
		keys := make([]string, 0, len(cfg.Env))
		for key := range cfg.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b.WriteString("Environment=\"" + systemdEscape(key+"="+cfg.Env[key]) + "\"\n")
		}
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.Bytes()
}

func systemdEscape(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	return v
}
