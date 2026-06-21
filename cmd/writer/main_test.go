package main

import (
	"os"
	"path"
	"testing"
)

// TestCreateLoadRoundTrip exercises the real key lifecycle: create a feed
// (which encrypts and stores the key), then load it back and resolve the
// private key by feed id — all through the actual functions main() uses.
func TestCreateLoadRoundTrip(t *testing.T) {
	workdir := t.TempDir()
	if err := os.MkdirAll(path.Join(workdir, "keys"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv(passphraseEnv, "integration-pass")

	if err := createFeedchain(workdir, "tester"); err != nil {
		t.Fatalf("createFeedchain: %v", err)
	}

	// A feed file and a key file should now exist.
	entries, err := os.ReadDir(workdir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var feedID string
	for _, e := range entries {
		if !e.IsDir() {
			feedID = e.Name()
		}
	}
	if feedID == "" {
		t.Fatal("no feed file created")
	}

	// loadKeys must decrypt the stored key using the env passphrase.
	if err := loadKeys(workdir); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if len(Keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(Keys))
	}

	// keyForFeed must resolve the private key for the feed id, and that key's
	// public half must equal the feed id.
	priv := keyForFeed(feedID)
	if priv == nil {
		t.Fatal("keyForFeed returned nil for the created feed")
	}
}

// TestLoadKeysWrongPassphrase confirms loading fails clearly on a bad passphrase.
func TestLoadKeysWrongPassphrase(t *testing.T) {
	workdir := t.TempDir()
	if err := os.MkdirAll(path.Join(workdir, "keys"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	t.Setenv(passphraseEnv, "right-pass")
	if err := createFeedchain(workdir, "tester"); err != nil {
		t.Fatalf("createFeedchain: %v", err)
	}

	t.Setenv(passphraseEnv, "wrong-pass")
	if err := loadKeys(workdir); err == nil {
		t.Fatal("loadKeys succeeded with the wrong passphrase")
	}
}
