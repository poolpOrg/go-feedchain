package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path"
	"testing"
)

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	priv := genKey(t)
	pass := []byte("correct horse battery staple")

	enc, err := encryptKey(priv, pass)
	if err != nil {
		t.Fatalf("encryptKey: %v", err)
	}
	// The plaintext private key must not appear in the ciphertext file.
	if containsBytes(enc, priv) {
		t.Fatal("encrypted blob contains the raw private key")
	}

	got, err := decryptKey(enc, pass)
	if err != nil {
		t.Fatalf("decryptKey: %v", err)
	}
	if !priv.Equal(got) {
		t.Fatal("round-tripped key does not match original")
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	priv := genKey(t)
	enc, err := encryptKey(priv, []byte("right"))
	if err != nil {
		t.Fatalf("encryptKey: %v", err)
	}
	if _, err := decryptKey(enc, []byte("wrong")); err == nil {
		t.Fatal("decryptKey accepted a wrong passphrase")
	}
}

func TestDecryptTamperDetected(t *testing.T) {
	priv := genKey(t)
	enc, err := encryptKey(priv, []byte("pw"))
	if err != nil {
		t.Fatalf("encryptKey: %v", err)
	}
	// Flip a bit in the ciphertext; GCM must reject it.
	enc[len(enc)-1] ^= 0x01
	if _, err := decryptKey(enc, []byte("pw")); err == nil {
		t.Fatal("decryptKey accepted tampered ciphertext")
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	if _, err := decryptKey([]byte("not a key file at all"), []byte("pw")); err == nil {
		t.Fatal("decryptKey accepted non-key bytes")
	}
	if _, err := decryptKey(nil, []byte("pw")); err == nil {
		t.Fatal("decryptKey accepted empty input")
	}
}

func TestWriteEncryptedKeyFilenameIsPublicKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(path.Join(dir, "keys"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	priv := genKey(t)
	pass := []byte("pw")

	if err := writeEncryptedKey(dir, priv, pass); err != nil {
		t.Fatalf("writeEncryptedKey: %v", err)
	}

	entries, err := os.ReadDir(path.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 key file, got %d", len(entries))
	}
	name := entries[0].Name()

	// The filename must decode to the 32-byte public key, never the 64-byte
	// private key (the legacy leak).
	decoded, err := base64.RawURLEncoding.DecodeString(name)
	if err != nil {
		t.Fatalf("filename is not base64 RawURL: %v", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("filename decodes to %d bytes, want public key size %d", len(decoded), ed25519.PublicKeySize)
	}
	if string(decoded) == string(priv) {
		t.Fatal("filename is the private key; key leaked in filename")
	}

	// File perms must be 0600.
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file perms = %o, want 600", perm)
	}

	// And the contents must decrypt back to the original key.
	data, err := os.ReadFile(path.Join(dir, "keys", name))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got, err := decryptKey(data, pass)
	if err != nil {
		t.Fatalf("decryptKey: %v", err)
	}
	if !priv.Equal(got) {
		t.Fatal("stored key does not round-trip")
	}
}

// containsBytes reports whether sub appears anywhere in b.
func containsBytes(b, sub []byte) bool {
	if len(sub) == 0 || len(sub) > len(b) {
		return false
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}
