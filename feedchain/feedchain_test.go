package feedchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestFeed creates an in-memory writer backed by a temp file with n appended blocks.
func newTestFeed(t *testing.T, n int) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := Init(priv)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	w.Metadata.Name = "tester"
	for i := 0; i < n; i++ {
		if err := w.Append("message #" + string(rune('0'+i)) + " #tag @ref"); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), w.ID())
	if err := w.Commit(path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return priv, path
}

// TestRoundTrip is the happy-path: write a feed, read it back, verify every block.
func TestRoundTrip(t *testing.T) {
	_, path := newTestFeed(t, 3)

	rd, err := NewReaderFromFile(path)
	if err != nil {
		t.Fatalf("NewReaderFromFile: %v", err)
	}
	defer rd.Close()

	if rd.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", rd.Size())
	}
	if rd.Metadata.Name != "tester" {
		t.Errorf("Metadata.Name = %q, want %q", rd.Metadata.Name, "tester")
	}

	for i := uint64(0); i < rd.Size(); i++ {
		block, err := rd.Offset(i)
		if err != nil {
			t.Fatalf("Offset(%d): %v", i, err)
		}
		if !rd.Verify(block) {
			t.Errorf("Verify(block %d) = false, want true", i)
		}
	}
}

// TestNextIteratesAllBlocks documents the Next() off-by-one bug.
// Starting from a fresh reader, Next() should yield every block exactly once,
// beginning with block 0. The current implementation starts at cursor+1.
func TestNextIteratesAllBlocks(t *testing.T) {
	_, path := newTestFeed(t, 3)
	rd, err := NewReaderFromFile(path)
	if err != nil {
		t.Fatalf("NewReaderFromFile: %v", err)
	}
	defer rd.Close()

	// Block 0 directly, for comparison.
	first, err := rd.Offset(0)
	if err != nil {
		t.Fatalf("Offset(0): %v", err)
	}

	got, err := rd.Next()
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}
	if got.ID() != first.ID() {
		t.Errorf("first Next() returned block %q, want block 0 %q (off-by-one: cursor starts at 0 but Next reads cursor+1)",
			got.ID()[:8], first.ID()[:8])
	}
}

// TestMentionIndex verifies Mention() populates the Mentions map (and only that map).
func TestMentionIndex(t *testing.T) {
	idx := NewIndex()
	var checksum [32]byte
	checksum[0] = 0xAB

	idx.Mention("alice", checksum)

	if len(idx.Mentions["alice"]) != 1 {
		t.Errorf("Mentions[alice] = %v, want 1 entry", idx.Mentions["alice"])
	}
	if len(idx.References["alice"]) != 0 {
		t.Errorf("Mention() leaked into References[alice] = %v, want empty", idx.References["alice"])
	}
}

// TestSearchHashtag exercises the index search path.
func TestSearchHashtag(t *testing.T) {
	idx := NewIndex()
	var checksum [32]byte
	checksum[0] = 0x01
	idx.Tag("golang", checksum)

	if hits := idx.Search("#golang"); len(hits) != 1 {
		t.Errorf("Search(#golang) = %v, want 1 hit", hits)
	}
	if hits := idx.Search("#missing"); hits != nil {
		t.Errorf("Search(#missing) = %v, want nil", hits)
	}
}

// TestTamperDetection ensures a corrupted block fails verification on read.
func TestTamperDetection(t *testing.T) {
	priv, path := newTestFeed(t, 1)
	_ = priv

	rd, err := NewReaderFromFile(path)
	if err != nil {
		t.Fatalf("NewReaderFromFile: %v", err)
	}
	defer rd.Close()

	block, err := rd.Offset(0)
	if err != nil {
		t.Fatalf("Offset(0): %v", err)
	}
	// Tamper in memory and confirm Verify rejects it.
	block.Message = "tampered"
	if rd.Verify(block) {
		t.Errorf("Verify() accepted a tampered block")
	}
}

// TestReadOverHTTP serves a feed file over a real HTTP server (supporting Range
// requests) and reads it back via NewReaderFromURL. This exercises the
// HTTPReader Range/io.ReadFull path that previously requested one byte too many
// and could short-read.
func TestReadOverHTTP(t *testing.T) {
	_, path := newTestFeed(t, 4)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "feed", time.Time{}, bytes.NewReader(data))
	}))
	defer srv.Close()

	rd, err := NewReaderFromURL(srv.URL)
	if err != nil {
		t.Fatalf("NewReaderFromURL: %v", err)
	}
	defer rd.Close()

	if rd.Size() != 4 {
		t.Fatalf("Size() = %d, want 4", rd.Size())
	}
	for i := uint64(0); i < rd.Size(); i++ {
		block, err := rd.Offset(i)
		if err != nil {
			t.Fatalf("Offset(%d) over HTTP: %v", i, err)
		}
		if !rd.Verify(block) {
			t.Errorf("Verify(block %d) over HTTP = false", i)
		}
	}
}

// TestMetadataSet covers the Set accessor and its unknown-key error.
func TestMetadataSet(t *testing.T) {
	m := NewMetadata()
	if err := m.Set("name", "alice"); err != nil {
		t.Fatalf("Set(name): %v", err)
	}
	if m.Name != "alice" {
		t.Errorf("Name = %q, want alice", m.Name)
	}
	if err := m.Set("bogus", "x"); err == nil {
		t.Errorf("Set(bogus) = nil error, want error for unknown key")
	}
}

// TestNewBlockFromBytesError confirms malformed JSON yields an error rather than
// killing the process (the old log.Fatal/panic behavior).
func TestNewBlockFromBytesError(t *testing.T) {
	if _, err := NewBlockFromBytes([]byte("{not json")); err == nil {
		t.Errorf("NewBlockFromBytes(garbage) = nil error, want error")
	}
	if _, err := NewBlockFromBytes([]byte(`{"message":"ok"}`)); err != nil {
		t.Errorf("NewBlockFromBytes(valid) = %v, want nil", err)
	}
}

// TestHeaderRoundTrip guards the hand-maintained header wire layout: every
// field must survive ToBytes -> NewHeaderFromBytes unchanged, and the computed
// end offset must equal the declared HeaderSize.
func TestHeaderRoundTrip(t *testing.T) {
	if headerEnd != HeaderSize {
		t.Fatalf("header layout offsets sum to %d, but HeaderSize = %d", headerEnd, HeaderSize)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	orig := &Header{
		Version:        HeaderVersion,
		GenerationTime: 1234567890,
		IndexOffset:    111,
		IndexLength:    222,
		MetadataOffset: 333,
		MetadataLength: 444,
		PublicKey:      pub,
	}
	for i := range orig.IndexChecksum {
		orig.IndexChecksum[i] = byte(i)
		orig.MetadataChecksum[i] = byte(i + 100)
	}
	for i := range orig.IndexSignature {
		orig.IndexSignature[i] = byte(i + 1)
		orig.MetadataSignature[i] = byte(i + 2)
	}

	got := NewHeaderFromBytes(orig.ToBytes())

	if got.Version != orig.Version || got.GenerationTime != orig.GenerationTime ||
		got.IndexOffset != orig.IndexOffset || got.IndexLength != orig.IndexLength ||
		got.MetadataOffset != orig.MetadataOffset || got.MetadataLength != orig.MetadataLength {
		t.Errorf("scalar fields did not round-trip: got %+v", got)
	}
	if got.IndexChecksum != orig.IndexChecksum || got.MetadataChecksum != orig.MetadataChecksum ||
		got.IndexSignature != orig.IndexSignature || got.MetadataSignature != orig.MetadataSignature {
		t.Errorf("checksum/signature fields did not round-trip")
	}
	if !got.PublicKey.Equal(orig.PublicKey) {
		t.Errorf("public key did not round-trip")
	}
}

// TestIndexSignatureVerifiedOnRead confirms the reader rejects a feed whose
// index signature is invalid even though the header is validly signed and the
// index checksum still matches. This isolates the index-signature check added
// to NewReader: we corrupt only the IndexSignature, then re-sign the header
// with the real key so the header check passes and the index-signature check
// is the one that must fail.
func TestIndexSignatureVerifiedOnRead(t *testing.T) {
	priv, path := newTestFeed(t, 2)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Parse the header, corrupt the index signature, and re-pack.
	var headerBuf [HeaderSize]byte
	copy(headerBuf[:], data[SignatureSize:SignatureSize+HeaderSize])
	header := NewHeaderFromBytes(headerBuf)
	header.IndexSignature[0] ^= 0xFF // now an invalid signature for IndexChecksum
	newHeader := header.ToBytes()

	// Re-sign the header so the header signature check (which runs first) passes.
	newHeaderChecksum := sha256.Sum256(newHeader[:])
	newHeaderSig := ed25519.Sign(priv, newHeaderChecksum[:])

	copy(data[0:SignatureSize], newHeaderSig)
	copy(data[SignatureSize:SignatureSize+HeaderSize], newHeader[:])

	tmp := filepath.Join(t.TempDir(), "corrupt")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = NewReaderFromFile(tmp)
	if err == nil {
		t.Fatal("NewReaderFromFile accepted a feed with a corrupted index signature")
	}
	if err.Error() != "index signature verification failed" {
		t.Errorf("error = %q, want index signature verification failed", err)
	}
}
