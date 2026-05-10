package udpserver

import (
	"testing"

	"masterdnsvpn-go/internal/security"
)

const testEncryptionKey = "0123456789abcdef0123456789abcdef"

func newTestCodec(t *testing.T) *security.Codec {
	t.Helper()

	codec, err := security.NewCodec(5, testEncryptionKey)
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}
	return codec
}
