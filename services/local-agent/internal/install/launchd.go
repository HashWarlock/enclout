package install

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, string(out))
	}
	return nil
}

type launchdInstaller struct {
	runner commandRunner
	uid    int
}

func NewLaunchdInstaller() ServiceInstaller {
	return newLaunchdInstaller(osCommandRunner{}, os.Getuid())
}

func newLaunchdInstaller(runner commandRunner, uid int) *launchdInstaller {
	return &launchdInstaller{
		runner: runner,
		uid:    uid,
	}
}

func (i *launchdInstaller) InstallAndStart(ctx context.Context, cfg ServiceConfig) error {
	plistData, err := renderLaunchdPlist(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.PlistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.PlistPath, plistData, 0o644); err != nil {
		return err
	}

	guiTarget := "gui/" + strconv.Itoa(i.uid)
	serviceTarget := guiTarget + "/" + cfg.Label

	// Best-effort cleanup for existing job.
	_ = i.runner.Run(ctx, "launchctl", "bootout", guiTarget, cfg.PlistPath)
	if err := i.runner.Run(ctx, "launchctl", "bootstrap", guiTarget, cfg.PlistPath); err != nil {
		return err
	}
	if err := i.runner.Run(ctx, "launchctl", "enable", serviceTarget); err != nil {
		return err
	}
	if err := i.runner.Run(ctx, "launchctl", "kickstart", "-k", serviceTarget); err != nil {
		return err
	}
	return nil
}

func renderLaunchdPlist(cfg ServiceConfig) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString(`<dict>` + "\n")
	writePlistKeyString(&b, "Label", cfg.Label)
	b.WriteString(`<key>ProgramArguments</key>` + "\n")
	b.WriteString(`<array>` + "\n")
	writePlistString(&b, cfg.AgentBinary)
	b.WriteString(`</array>` + "\n")
	b.WriteString(`<key>RunAtLoad</key>` + "\n" + `<true/>` + "\n")
	b.WriteString(`<key>KeepAlive</key>` + "\n" + `<true/>` + "\n")
	if len(cfg.Env) > 0 {
		b.WriteString(`<key>EnvironmentVariables</key>` + "\n")
		b.WriteString(`<dict>` + "\n")
		keys := make([]string, 0, len(cfg.Env))
		for key := range cfg.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			writePlistKeyString(&b, key, cfg.Env[key])
		}
		b.WriteString(`</dict>` + "\n")
	}
	b.WriteString(`</dict>` + "\n")
	b.WriteString(`</plist>` + "\n")
	return b.Bytes(), nil
}

func writePlistKeyString(b *bytes.Buffer, key string, value string) {
	b.WriteString(`<key>` + xmlEscape(key) + `</key>` + "\n")
	writePlistString(b, value)
}

func writePlistString(b *bytes.Buffer, value string) {
	b.WriteString(`<string>` + xmlEscape(value) + `</string>` + "\n")
}

func xmlEscape(v string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(v))
	return escaped.String()
}
