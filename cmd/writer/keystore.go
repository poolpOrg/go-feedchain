package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path"

	"golang.org/x/term"
)

// Encrypted key file format (raw bytes, written 0600):
//
//	magic(8) || version(1) || salt(16) || nonce(12) || ciphertext
//
// The ciphertext is the ed25519 private key sealed with AES-256-GCM. The key is
// derived from the passphrase with PBKDF2-HMAC-SHA256. The file is named after
// the *public* key (the feed id), which is safe to expose; the private key
// never appears in a filename.
const (
	keyMagic      = "FCKEYS01"
	keyVersion    = 1
	keySaltLen    = 16
	keyNonceLen   = 12
	keyKDFIters   = 600_000
	keyDerivedLen = 32 // AES-256
)

// passphraseEnv lets non-interactive callers (scripts, tests) supply the
// passphrase without a terminal prompt.
const passphraseEnv = "FEEDCHAIN_PASSPHRASE"

// readPassphrase returns the passphrase from the environment if set, otherwise
// prompts for it on the terminal without echoing. When confirm is true (key
// creation) it asks twice and checks the two entries match.
func readPassphrase(confirm bool) ([]byte, error) {
	if env := os.Getenv(passphraseEnv); env != "" {
		return []byte(env), nil
	}

	fmt.Fprint(os.Stderr, "passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("empty passphrase")
	}

	if confirm {
		fmt.Fprint(os.Stderr, "confirm passphrase: ")
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if string(pass) != string(again) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return pass, nil
}

// deriveKey turns a passphrase + salt into an AES-256 key.
func deriveKey(passphrase, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(passphrase), salt, keyKDFIters, keyDerivedLen)
}

// encryptKey seals priv under passphrase and returns the on-disk file bytes.
func encryptKey(priv ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	salt := make([]byte, keySaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dk, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, keyNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, priv, nil)

	out := make([]byte, 0, len(keyMagic)+1+keySaltLen+keyNonceLen+len(ciphertext))
	out = append(out, []byte(keyMagic)...)
	out = append(out, keyVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptKey opens an encrypted key file's bytes with passphrase.
func decryptKey(data, passphrase []byte) (ed25519.PrivateKey, error) {
	hdr := len(keyMagic) + 1 + keySaltLen + keyNonceLen
	if len(data) < hdr {
		return nil, fmt.Errorf("key file too short")
	}
	if string(data[:len(keyMagic)]) != keyMagic {
		return nil, fmt.Errorf("not a feedchain key file")
	}
	if data[len(keyMagic)] != keyVersion {
		return nil, fmt.Errorf("unsupported key file version %d", data[len(keyMagic)])
	}
	off := len(keyMagic) + 1
	salt := data[off : off+keySaltLen]
	off += keySaltLen
	nonce := data[off : off+keyNonceLen]
	off += keyNonceLen
	ciphertext := data[off:]

	dk, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt key (wrong passphrase?)")
	}
	if len(plain) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decrypted key has wrong size")
	}
	return ed25519.PrivateKey(plain), nil
}

// writeEncryptedKey encrypts priv and writes it to keys/<publicKey> with 0600.
func writeEncryptedKey(workdir string, priv ed25519.PrivateKey, passphrase []byte) error {
	enc, err := encryptKey(priv, passphrase)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	name := base64.RawURLEncoding.EncodeToString(pub)
	return os.WriteFile(path.Join(workdir, "keys", name), enc, 0600)
}
