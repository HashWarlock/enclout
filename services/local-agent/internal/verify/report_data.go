package verify

import "crypto/sha256"

func ComputeExpectedReportData(sshPublicKey string) [64]byte {
	var out [64]byte
	sum := sha256.Sum256([]byte(sshPublicKey))
	copy(out[:32], sum[:])
	return out
}
