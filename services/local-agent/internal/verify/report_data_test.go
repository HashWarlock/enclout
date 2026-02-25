package verify

import "testing"

func TestReportDataBinding(t *testing.T) {
	got := ComputeExpectedReportData("ssh-ed25519 AAAATEST connector@tee")
	if len(got) != 64 {
		t.Fatalf("expected 64-byte report data")
	}
	allZero := true
	for _, b := range got[:32] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("expected non-zero hash prefix in first 32 bytes")
	}
}
