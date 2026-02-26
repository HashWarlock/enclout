package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdInstallerWritesUnitAndRunsSystemctl(t *testing.T) {
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "ai.enclout.agent.service")
	runner := &fakeCommandRunner{}
	installer := newSystemdInstaller(runner)

	err := installer.InstallAndStart(context.Background(), ServiceConfig{
		Label:       "ai.enclout.agent",
		AgentBinary: "/usr/local/bin/enclout-agent",
		PlistPath:   unitPath,
		Env: map[string]string{
			"CONTROL_PLANE_URL": "http://127.0.0.1:8080",
			"DEVICE_ID":         "dev_1",
		},
	})
	if err != nil {
		t.Fatalf("unexpected install error: %v", err)
	}

	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	unit := string(raw)
	if !strings.Contains(unit, "Description=Enclout Local Agent") {
		t.Fatalf("expected unit description, got: %s", unit)
	}
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/enclout-agent") {
		t.Fatalf("expected exec start, got: %s", unit)
	}
	if !strings.Contains(unit, "Environment=\"CONTROL_PLANE_URL=http://127.0.0.1:8080\"") {
		t.Fatalf("expected env line, got: %s", unit)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 systemctl calls, got %d", len(runner.calls))
	}
	if runner.calls[0].name != "systemctl" || runner.calls[0].args[0] != "--user" || runner.calls[0].args[1] != "daemon-reload" {
		t.Fatalf("unexpected first call: %#v", runner.calls[0])
	}
	if runner.calls[1].name != "systemctl" || runner.calls[1].args[0] != "--user" || runner.calls[1].args[1] != "enable" || runner.calls[1].args[2] != "--now" || runner.calls[1].args[3] != "ai.enclout.agent.service" {
		t.Fatalf("unexpected second call: %#v", runner.calls[1])
	}
}
