package main

import (
	"bytes"
	"io"
	"os"
	"sync"

	"github.com/poolpOrg/feedchain/feedchain"
)

// feedCache memoizes the raw bytes of feed files so that repeated requests do
// not re-read them from disk. Each request still gets its own StreamReader
// (parsed over an in-memory bytes.Reader), because a StreamReader holds a
// stateful seek cursor and is not safe for concurrent use.
//
// Cache entries are keyed by path and invalidated by file size + modification
// time, so a republished feed (same path, new contents) is picked up
// automatically on the next request.
type feedCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	size    int64
	modTime int64 // UnixNano
	data    []byte
}

func newFeedCache() *feedCache {
	return &feedCache{entries: make(map[string]*cacheEntry)}
}

// nopCloserReadSeeker adapts a *bytes.Reader to io.ReadSeekCloser.
type nopCloserReadSeeker struct {
	*bytes.Reader
}

func (nopCloserReadSeeker) Close() error { return nil }

// reader returns a freshly parsed StreamReader for the feed at path, reading
// the file from disk only when the cached copy is missing or stale.
func (c *feedCache) reader(path string) (*feedchain.StreamReader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	size := info.Size()
	modTime := info.ModTime().UnixNano()

	c.mu.RLock()
	entry, ok := c.entries[path]
	c.mu.RUnlock()

	if !ok || entry.size != size || entry.modTime != modTime {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		entry = &cacheEntry{size: size, modTime: modTime, data: data}
		c.mu.Lock()
		c.entries[path] = entry
		c.mu.Unlock()
	}

	rd := nopCloserReadSeeker{bytes.NewReader(entry.data)}
	return feedchain.NewReader(rd)
}

// invalidate drops any cached copy of path. Called after a successful upload so
// the new contents are served immediately rather than on the next mtime change.
func (c *feedCache) invalidate(path string) {
	c.mu.Lock()
	delete(c.entries, path)
	c.mu.Unlock()
}

var _ io.ReadSeekCloser = nopCloserReadSeeker{}
