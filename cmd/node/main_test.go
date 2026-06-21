package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/poolpOrg/feedchain/feedchain"
)

// makeFeed builds a small valid feed and returns its id and raw bytes.
func makeFeed(t *testing.T) (string, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := feedchain.Init(priv)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	w.Metadata.Name = "tester"
	if err := w.Append("hello world"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	path := filepath.Join(t.TempDir(), w.ID())
	if err := w.Commit(path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return w.ID(), data
}

// setupServer points repositoryPath at a fresh temp dir and returns a test server.
func setupServer(t *testing.T) *httptest.Server {
	t.Helper()
	repositoryPath = t.TempDir()
	srv := httptest.NewServer(newRouter())
	t.Cleanup(srv.Close)
	return srv
}

// TestPostAndGetRoundTrip posts a feed and reads it back.
func TestPostAndGetRoundTrip(t *testing.T) {
	srv := setupServer(t)
	feedId, data := makeFeed(t)

	resp, err := http.Post(srv.URL+"/"+feedId, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}

	// The feed should now exist on disk under its id.
	if _, err := os.Stat(filepath.Join(repositoryPath, feedId)); err != nil {
		t.Fatalf("feed not stored: %v", err)
	}

	// And be retrievable via GET.
	resp, err = http.Get(srv.URL + "/" + feedId)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
}

// TestPostTooLarge confirms an oversize upload is rejected, not written.
func TestPostTooLarge(t *testing.T) {
	srv := setupServer(t)

	huge := bytes.NewReader(make([]byte, maxFeedSize+1024))
	resp, err := http.Post(srv.URL+"/"+strings.Repeat("A", 43), "application/octet-stream", huge)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize POST status = %d, want 413", resp.StatusCode)
	}

	// Nothing should have been left in the repository.
	entries, _ := os.ReadDir(repositoryPath)
	if len(entries) != 0 {
		t.Errorf("oversize upload left %d files in repo, want 0", len(entries))
	}
}

// TestInvalidFeedID confirms a traversal/garbage id is rejected before any
// filesystem access.
func TestInvalidFeedID(t *testing.T) {
	srv := setupServer(t)

	// Note: a literal "/.." is normalized to "/" by path cleaning before it
	// reaches the handler, so it is not a reachable traversal vector. These
	// values do reach serveFeed as the {feedId} var and must be rejected by
	// the validFeedID guard.
	for _, id := range []string{"not-a-key", strings.Repeat("A", 10), strings.Repeat("A", 44), "AAAA.AAAA"} {
		resp, err := http.Get(srv.URL + "/" + id)
		if err != nil {
			t.Fatalf("GET %q: %v", id, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET %q status = %d, want 400", id, resp.StatusCode)
		}
	}
}

// TestPostWrongID confirms a feed posted to a path that does not match its
// public key is refused.
func TestPostWrongID(t *testing.T) {
	srv := setupServer(t)
	_, data := makeFeed(t)

	// A syntactically valid but wrong id (43 chars, valid alphabet).
	wrongID := strings.Repeat("B", 43)
	resp, err := http.Post(srv.URL+"/"+wrongID, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("mismatched POST status = %d, want 403", resp.StatusCode)
	}
}

// TestCORSNoCredentials confirms the invalid wildcard+credentials combo is gone.
func TestCORSNoCredentials(t *testing.T) {
	srv := setupServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want unset", got)
	}
}
