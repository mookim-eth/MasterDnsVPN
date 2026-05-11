package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"masterdnsvpn-go/internal/config"
)

func TestEnsureServerEncryptionKeyGeneratesFullEntropyAES256Text(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ServerConfig{
		ConfigDir:            dir,
		DataEncryptionMethod: 5,
		EncryptionKeyFile:    "encrypt_key.txt",
	}

	info, err := EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("EnsureServerEncryptionKey returned error: %v", err)
	}
	if !info.Generated || info.Loaded {
		t.Fatalf("expected a generated key, info=%+v", info)
	}
	if info.RecommendedLength != 64 {
		t.Fatalf("unexpected recommended key length: got=%d want=64", info.RecommendedLength)
	}
	if len(info.Key) != 64 {
		t.Fatalf("AES-256-GCM generated key text must be 64 hex chars, got=%d", len(info.Key))
	}
	if info.LegacyLength {
		t.Fatal("newly generated key must not be marked as legacy")
	}

	raw, err := os.ReadFile(filepath.Join(dir, "encrypt_key.txt"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if strings.TrimSpace(string(raw)) != info.Key {
		t.Fatal("key file does not contain the generated key")
	}
}

func TestEnsureServerEncryptionKeyLoadsLegacyAES256KeyWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "encrypt_key.txt")
	legacyKey := strings.Repeat("a", 32)
	if err := os.WriteFile(keyPath, []byte(legacyKey), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg := config.ServerConfig{
		ConfigDir:            dir,
		DataEncryptionMethod: 5,
		EncryptionKeyFile:    "encrypt_key.txt",
	}
	info, err := EnsureServerEncryptionKey(cfg)
	if err != nil {
		t.Fatalf("EnsureServerEncryptionKey returned error: %v", err)
	}
	if !info.Loaded || info.Generated {
		t.Fatalf("expected legacy key to be loaded without regeneration, info=%+v", info)
	}
	if !info.LegacyLength {
		t.Fatal("expected legacy key length to be flagged")
	}
	if info.Key != legacyKey {
		t.Fatalf("unexpected loaded key: got=%q want=%q", info.Key, legacyKey)
	}

	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if strings.TrimSpace(string(raw)) != legacyKey {
		t.Fatal("legacy key file should not be overwritten implicitly")
	}
}
