package requests

import (
	"crypto/rand"
	"encoding/hex"
)

func randomID() string {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(buf)
}
