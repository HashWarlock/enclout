package main

import "testing"

func TestDefaultPlistPath(t *testing.T) {
	got := defaultPlistPath("/Users/alice", "ai.enclout.agent")
	want := "/Users/alice/Library/LaunchAgents/ai.enclout.agent.plist"
	if got != want {
		t.Fatalf("unexpected plist path: got %q want %q", got, want)
	}
}

func TestBuildInstallEnvIncludesRequiredAndOptional(t *testing.T) {
	env := map[string]string{
		"AGENT_TOKEN":                     "tok",
		"DCAP_VERIFIER_TIMEOUT":           "15s",
		"CONTROL_PLANE_SIGNING_KEYS_JSON": `{"v1":"AAAA"}`,
		"SIGNING_KEYSET_CACHE_TTL":        "5m",
	}

	got := buildInstallEnv("alice", "http://127.0.0.1:8080", "http://127.0.0.1:9000", func(key string) string {
		return env[key]
	})

	if got["CONTROL_PLANE_URL"] != "http://127.0.0.1:8080" {
		t.Fatalf("missing CONTROL_PLANE_URL")
	}
	if got["LOCAL_USERNAME"] != "alice" {
		t.Fatalf("missing LOCAL_USERNAME")
	}
	if got["DCAP_VERIFIER_URL"] != "http://127.0.0.1:9000" {
		t.Fatalf("missing DCAP_VERIFIER_URL")
	}
	if got["AGENT_TOKEN"] != "tok" {
		t.Fatalf("missing optional AGENT_TOKEN")
	}
	if got["SIGNING_KEYSET_CACHE_TTL"] != "5m" {
		t.Fatalf("missing optional SIGNING_KEYSET_CACHE_TTL")
	}
}
