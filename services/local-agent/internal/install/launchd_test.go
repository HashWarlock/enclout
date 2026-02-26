package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type commandCall struct {
	name string
	args []string
}

type fakeCommandRunner struct {
	calls []commandCall
	fail  map[int]error
}

func (f *fakeCommandRunner) Run(_ context.Context, name string, args ...string) error {
	idx := len(f.calls)
	f.calls = append(f.calls, commandCall{name: name, args: args})
	if err, ok := f.fail[idx]; ok {
		return err
	}
	return nil
}

func TestLaunchdInstallerWritesPlistAndRunsLaunchctlSequence(t *testing.T) {
	dir := t.TempDir()
	plistPath := filepath.Join(dir, "ai.enclout.agent.plist")
	runner := &fakeCommandRunner{}
	installer := newLaunchdInstaller(runner, 501)

	err := installer.InstallAndStart(context.Background(), ServiceConfig{
		Label:       "ai.enclout.agent",
		AgentBinary: "/usr/local/bin/enclout-agent",
		PlistPath:   plistPath,
		Env: map[string]string{
			"CONTROL_PLANE_URL": "http://127.0.0.1:8080",
			"DEVICE_ID":         "dev_1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected install error: %v", err)
	}

	raw, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("unexpected plist read error: %v", err)
	}
	plist := string(raw)
	if !strings.Contains(plist, "<string>ai.enclout.agent</string>") {
		t.Fatalf("expected label in plist, got: %s", plist)
	}
	if !strings.Contains(plist, "<string>/usr/local/bin/enclout-agent</string>") {
		t.Fatalf("expected program in plist, got: %s", plist)
	}

	if len(runner.calls) != 4 {
		t.Fatalf("expected 4 launchctl calls, got %d", len(runner.calls))
	}
	if runner.calls[0].name != "launchctl" || runner.calls[0].args[0] != "bootout" {
		t.Fatalf("expected first call launchctl bootout, got %#v", runner.calls[0])
	}
	if runner.calls[1].args[0] != "bootstrap" {
		t.Fatalf("expected second call bootstrap, got %#v", runner.calls[1])
	}
	if runner.calls[2].args[0] != "enable" {
		t.Fatalf("expected third call enable, got %#v", runner.calls[2])
	}
	if runner.calls[3].args[0] != "kickstart" {
		t.Fatalf("expected fourth call kickstart, got %#v", runner.calls[3])
	}
}
