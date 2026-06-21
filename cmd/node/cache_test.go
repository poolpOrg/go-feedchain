package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/poolpOrg/feedchain/feedchain"
)

// writeFeed builds a feed with the given message and writes it to path.
func writeFeed(t *testing.T, path, msg string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := feedchain.Init(priv)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := w.Append(msg); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Commit(path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return w.ID()
}

// TestCacheReaderRoundTrip confirms the cache returns a usable reader and that
// repeated reads work (independent readers, no shared cursor).
func TestCacheReaderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed")
	writeFeed(t, path, "hello")

	c := newFeedCache()

	// Two readers obtained back-to-back must each see the block independently.
	for i := 0; i < 2; i++ {
		rd, err := c.reader(path)
		if err != nil {
			t.Fatalf("reader (iter %d): %v", i, err)
		}
		block, err := rd.Offset(0)
		if err != nil {
			t.Fatalf("Offset (iter %d): %v", i, err)
		}
		if block.Message != "hello" {
			t.Errorf("Message = %q, want hello", block.Message)
		}
		rd.Close()
	}

	// After the first read the path must be cached.
	if _, ok := c.entries[path]; !ok {
		t.Error("path was not cached after read")
	}
}

// TestCacheServesCachedBytes confirms a cache hit does NOT re-read the file: a
// second read of an unchanged file reuses the same backing byte slice.
func TestCacheServesCachedBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed")
	writeFeed(t, path, "original")

	c := newFeedCache()
	rd, err := c.reader(path)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	rd.Close()

	// Mutate the cached bytes in place; a cache hit should still return them
	// (proving it did not re-read from disk). We assert by checking the entry
	// data is reused rather than reloaded for an unchanged file.
	entry := c.entries[path]
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	originalData := entry.data

	rd2, err := c.reader(path)
	if err != nil {
		t.Fatalf("reader (2nd): %v", err)
	}
	rd2.Close()
	if &c.entries[path].data[0] != &originalData[0] {
		t.Error("cache re-read an unchanged file instead of serving the cached copy")
	}
}

// TestCacheInvalidate drops the entry so the next read reloads from disk.
func TestCacheInvalidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed")
	writeFeed(t, path, "v1")

	c := newFeedCache()
	if _, err := c.reader(path); err != nil {
		t.Fatalf("reader: %v", err)
	}
	if _, ok := c.entries[path]; !ok {
		t.Fatal("expected cache entry")
	}

	c.invalidate(path)
	if _, ok := c.entries[path]; ok {
		t.Error("entry still present after invalidate")
	}
}

// TestCacheRefreshesOnContentChange confirms rewriting the file with a forced
// mtime bump makes the cache serve the new content.
func TestCacheRefreshesOnContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feed")
	writeFeed(t, path, "first")

	c := newFeedCache()
	rd, err := c.reader(path)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	rd.Close()

	// Rewrite with new content and bump mtime so the size/mtime cache key
	// changes and the cache reloads from disk.
	writeFeed(t, path, "second message that is clearly longer")
	if err := os.Chtimes(path, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	rd2, err := c.reader(path)
	if err != nil {
		t.Fatalf("reader (2nd): %v", err)
	}
	defer rd2.Close()
	block, err := rd2.Offset(0)
	if err != nil {
		t.Fatalf("Offset: %v", err)
	}
	if block.Message != "second message that is clearly longer" {
		t.Errorf("Message = %q, want refreshed content", block.Message)
	}
}
