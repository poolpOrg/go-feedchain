package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/feeds"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/poolpOrg/feedchain/feedchain"
)

type FeedIndexRecord struct {
	CreationTime int64  `json:"creation_time"`
	Offset       uint64 `json:"offset"`
	Length       uint64 `json:"length"`
	Checksum     string `json:"digest"`
	Signature    string `json:"signature"`
}

type FeedIndex struct {
	Records    []FeedIndexRecord   `json:"records"`
	Hashtags   map[string][]string `json:"hashtags"`
	Mentions   map[string][]string `json:"mentions"`
	References map[string][]string `json:"references"`
	Threads    map[string][]string `json:"threads"`
	Digest     string              `json:"digest"`
	Signature  string              `json:"signature"`
}

type FeedBlockPayload struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
}

type FeedBlockPayloadSummary struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        uint64 `json:"size"`
}

type FeedBlock struct {
	CreationTime int64                     `json:"creation_time"`
	Message      string                    `json:"message"`
	Payload      []FeedBlockPayloadSummary `json:"payload"`
	Thread       string                    `json:"thread"`
	Parent       string                    `json:"parent"`
	Checksum     string                    `json:"digest"`
	Signature    string                    `json:"signature"`
}

type FeedSummary struct {
	PublicKey string `json:"public_key"`
	Size      int    `json:"length"`
}

var repositoryPath string

// cache memoizes parsed feed bytes to avoid re-reading every file on every
// request.
var cache = newFeedCache()

// maxFeedSize bounds how large a single posted feed may be, to prevent a
// disk-fill denial of service.
const maxFeedSize = 32 << 20 // 32 MiB

// validFeedID matches a feed identifier: a base64 RawURL-encoded ed25519
// public key (43 chars from the [A-Za-z0-9_-] alphabet). Constraining it here
// also prevents path traversal, since the id is used to build a filesystem
// path under repositoryPath.
var validFeedID = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// feedPath returns the on-disk path for feedId, or ok=false if feedId is not a
// well-formed feed identifier (which also guards against path traversal).
func feedPath(feedId string) (string, bool) {
	if !validFeedID.MatchString(feedId) {
		return "", false
	}
	return filepath.Join(repositoryPath, feedId), true
}

// openFeed validates feedId, opens and verifies the feed, and confirms its
// identity matches the request. On any failure it writes an appropriate HTTP
// error response and returns ok=false; callers should simply return.
func openFeed(w http.ResponseWriter, feedId string) (*feedchain.StreamReader, bool) {
	path, ok := feedPath(feedId)
	if !ok {
		http.Error(w, "invalid feed id", http.StatusBadRequest)
		return nil, false
	}
	feed, err := cache.reader(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if feed.ID() != feedId {
		feed.Close()
		http.Error(w, "feed id mismatch", http.StatusForbidden)
		return nil, false
	}
	return feed, true
}

func empty(w http.ResponseWriter, r *http.Request) {
}

func serveFeed(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]

	path, ok := feedPath(feedId)
	if !ok {
		http.Error(w, "invalid feed id", http.StatusBadRequest)
		return
	}

	if r.Method == "HEAD" || r.Method == "GET" {
		file, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
		} else if r.Method == "GET" {
			dataRange := r.Header.Get("Range")
			if dataRange == "" {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
				io.Copy(w, file)
				return
			}

			if !strings.HasPrefix(dataRange, "bytes=") {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			dataRange = dataRange[6:]
			tmp := strings.Split(dataRange, "-")
			if len(tmp) != 2 {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			beginOffset, err := strconv.Atoi(tmp[0])
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			endOffset, err := strconv.Atoi(tmp[1])
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if beginOffset < 0 || endOffset <= beginOffset {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			_, err = file.Seek(int64(beginOffset), 0)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			buf := make([]byte, endOffset-beginOffset)
			file.Read(buf)
			w.Write(buf)
		}
	} else if r.Method == "POST" {
		// Stage the upload inside the repository dir so the final rename is a
		// cheap same-filesystem operation, and so a failed upload never lands
		// in the served path.
		file, err := ioutil.TempFile(repositoryPath, ".feedchain.upload.")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(file.Name())

		// Bound the upload: an unbounded io.Copy from the request body is a
		// trivial disk-fill DoS. A LimitReader of maxFeedSize+1 lets us detect
		// oversize uploads rather than silently truncating them.
		limited := io.LimitReader(r.Body, maxFeedSize+1)
		written, err := io.Copy(file, limited)
		if err != nil {
			file.Close()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		file.Close()
		if written > maxFeedSize {
			http.Error(w, "feed too large", http.StatusRequestEntityTooLarge)
			return
		}

		feed, err := feedchain.NewReaderFromFile(file.Name())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// The feed self-certifies: its ID is its public key, and the whole file
		// is signature-verified by NewReaderFromFile. Reject a feed posted to
		// the wrong path.
		if feed.ID() != feedId {
			feed.Close()
			http.Error(w, "feed id does not match request path", http.StatusForbidden)
			return
		}
		feed.Close()

		dest := filepath.Join(repositoryPath, feed.ID())
		if err := os.Rename(file.Name(), dest); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Drop any stale cached copy so the new contents are served at once.
		cache.invalidate(dest)
	}
}

func apiLookup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	ret := make([]FeedSummary, 0)
	err := filepath.Walk(repositoryPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			feed, err := feedchain.NewReaderFromFile(path)
			if err != nil {
				return nil
			}
			defer feed.Close()

			if strings.ToLower(feed.Metadata.Name) != strings.ToLower(name) {
				return nil
			}

			feedSummary := FeedSummary{
				Size:      len(feed.Index.Records),
				PublicKey: feed.ID(),
			}

			ret = append(ret, feedSummary)
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(ret)
}

func apiFeed(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	feedIndex := FeedIndex{}
	feedIndex.Digest = feed.IndexChecksum
	feedIndex.Signature = feed.IndexSignature
	feedIndex.Records = make([]FeedIndexRecord, 0)
	feedIndex.Hashtags = make(map[string][]string)
	feedIndex.Mentions = make(map[string][]string)
	feedIndex.References = make(map[string][]string)
	feedIndex.Threads = make(map[string][]string)

	for _, record := range feed.Index.Records {
		feedIndex.Records = append(feedIndex.Records, FeedIndexRecord{
			CreationTime: record.CreationTime,
			Offset:       record.BlockOffset,
			Length:       record.BlockLen,
			Checksum:     record.BlockChecksum,
			Signature:    record.BlockSignature,
		})
	}

	for hashtag, checksums := range feed.Index.Hashtags {
		for _, checksum := range checksums {
			feedIndex.Hashtags[hashtag] = append(feedIndex.Hashtags[hashtag], checksum)
		}
	}

	for mention, checksums := range feed.Index.Mentions {
		for _, checksum := range checksums {
			feedIndex.Mentions[mention] = append(feedIndex.Mentions[mention], checksum)
		}
	}

	for reference, checksums := range feed.Index.References {
		for _, checksum := range checksums {
			feedIndex.References[reference] = append(feedIndex.References[reference], checksum)
		}
	}

	for thread, checksums := range feed.Index.Threads {
		for _, checksum := range checksums {
			feedIndex.Threads[thread] = append(feedIndex.Threads[thread], checksum)
		}
	}

	json.NewEncoder(w).Encode(feedIndex)
}

func apiFeedBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	blockId := vars["blockId"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	for i := 0; i < len(feed.Index.Records); i++ {
		record := feed.Index.Records[i]
		if record.BlockChecksum == blockId {
			block, err := feed.Offset(uint64(i))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			feedBlock := FeedBlock{}
			feedBlock.Checksum = blockId
			feedBlock.Signature = feed.Index.Records[i].BlockSignature
			feedBlock.CreationTime = block.CreationTime
			feedBlock.Message = block.Message
			feedBlock.Thread = block.Thread
			feedBlock.Parent = block.Parent

			feedBlock.Payload = make([]FeedBlockPayloadSummary, 0)
			for _, payload := range block.Payload {
				feedBlock.Payload = append(feedBlock.Payload, FeedBlockPayloadSummary{
					Name:        payload.Name,
					ContentType: payload.ContentType,
					Size:        uint64(len(payload.Data)),
				})
			}

			json.NewEncoder(w).Encode(feedBlock)
			return
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func apiFeedBlockPayloadOffset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	blockId := vars["blockId"]
	payloadOffset := vars["payloadOffset"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	payloadOffsetInt, err := strconv.Atoi(payloadOffset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if payloadOffsetInt < 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	for i := 0; i < len(feed.Index.Records); i++ {
		record := feed.Index.Records[i]
		if record.BlockChecksum == blockId {
			block, err := feed.Offset(uint64(i))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if payloadOffsetInt >= len(block.Payload) {
				http.Error(w, "", http.StatusNotFound)
				return
			}

			feedBlockPayload := FeedBlockPayload{
				Name:        block.Payload[payloadOffsetInt].Name,
				ContentType: block.Payload[payloadOffsetInt].ContentType,
				Data:        block.Payload[payloadOffsetInt].Data,
			}

			json.NewEncoder(w).Encode(feedBlockPayload)
			return
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func apiFeedBlockPayloadOffsetRaw(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	blockId := vars["blockId"]
	payloadOffset := vars["payloadOffset"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	payloadOffsetInt, err := strconv.Atoi(payloadOffset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if payloadOffsetInt < 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	for i := 0; i < len(feed.Index.Records); i++ {
		record := feed.Index.Records[i]
		if record.BlockChecksum == blockId {
			block, err := feed.Offset(uint64(i))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if payloadOffsetInt >= len(block.Payload) {
				http.Error(w, "", http.StatusNotFound)
				return
			}

			decoded, err := base64.RawURLEncoding.DecodeString(block.Payload[payloadOffsetInt].Data)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			w.Header().Add("Content-Type", block.Payload[payloadOffsetInt].ContentType)
			w.Header().Add("Content-Disposition", fmt.Sprintf("attachement;filename=\"%s\"", block.Payload[payloadOffsetInt].Name))
			w.Header().Add("Content-Length", fmt.Sprintf("%d", len(decoded)))

			w.Write(decoded)
			return
		}
	}
	http.Error(w, "", http.StatusNotFound)
}

func apiFeedOffset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	offset := vars["offset"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	offsetInt, err := strconv.Atoi(offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if offsetInt < 0 || offsetInt >= len(feed.Index.Records) {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	block, err := feed.Offset(uint64(offsetInt))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	feedBlock := FeedBlock{}
	feedBlock.Signature = feed.Index.Records[offsetInt].BlockSignature
	feedBlock.Checksum = feed.Index.Records[offsetInt].BlockChecksum
	feedBlock.CreationTime = block.CreationTime
	feedBlock.Message = block.Message
	feedBlock.Thread = block.Thread
	feedBlock.Parent = block.Parent

	feedBlock.Payload = make([]FeedBlockPayloadSummary, 0)
	for _, payload := range block.Payload {
		feedBlock.Payload = append(feedBlock.Payload, FeedBlockPayloadSummary{
			Name:        payload.Name,
			ContentType: payload.ContentType,
			Size:        uint64(len(payload.Data)),
		})
	}

	json.NewEncoder(w).Encode(feedBlock)
}

func apiFeedOffsetPayloadOffset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	offset := vars["offset"]
	payloadOffset := vars["payloadOffset"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	offsetInt, err := strconv.Atoi(offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if offsetInt < 0 || offsetInt >= len(feed.Index.Records) {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	payloadOffsetInt, err := strconv.Atoi(payloadOffset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if payloadOffsetInt < 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	block, err := feed.Offset(uint64(offsetInt))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if payloadOffsetInt >= len(block.Payload) {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	feedBlockPayload := FeedBlockPayload{
		Name:        block.Payload[payloadOffsetInt].Name,
		ContentType: block.Payload[payloadOffsetInt].ContentType,
		Data:        block.Payload[payloadOffsetInt].Data,
	}

	json.NewEncoder(w).Encode(feedBlockPayload)
}

func apiFeedOffsetPayloadOffsetRaw(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]
	offset := vars["offset"]
	payloadOffset := vars["payloadOffset"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	offsetInt, err := strconv.Atoi(offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if offsetInt < 0 || offsetInt >= len(feed.Index.Records) {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	payloadOffsetInt, err := strconv.Atoi(payloadOffset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if payloadOffsetInt < 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	block, err := feed.Offset(uint64(offsetInt))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if payloadOffsetInt >= len(block.Payload) {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(block.Payload[payloadOffsetInt].Data)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", block.Payload[payloadOffsetInt].ContentType)
	w.Header().Add("Content-Disposition", fmt.Sprintf("attachement;filename=\"%s\"", block.Payload[payloadOffsetInt].Name))
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(decoded)))

	w.Write(decoded)
}

func apiFeeds(w http.ResponseWriter, r *http.Request) {
	ret := make([]FeedSummary, 0)
	err := filepath.Walk(repositoryPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			feed, err := feedchain.NewReaderFromFile(path)
			if err != nil {
				return nil
			}
			defer feed.Close()

			feedSummary := FeedSummary{
				Size:      len(feed.Index.Records),
				PublicKey: feed.ID(),
			}

			ret = append(ret, feedSummary)
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(ret)
}

type RSSFeedsData struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func serveRSS(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]

	feed, ok := openFeed(w, feedId)
	if !ok {
		return
	}
	defer feed.Close()

	feedinfo := &feeds.Feed{
		Title:       feedId,
		Link:        &feeds.Link{Href: "/" + feedId},
		Description: feed.Metadata.Description,
		Author:      &feeds.Author{Name: feed.Metadata.Name},
		Created:     time.Now(),
	}

	var feedItems []*feeds.Item
	for i := 0; i < int(feed.Size()); i++ {
		block, err := feed.Offset(uint64(i))
		if err != nil {
			continue
		}
		feedItems = append(feedItems, &feeds.Item{
			Id:          block.ID(),
			Title:       block.Message,
			Link:        &feeds.Link{Href: "//" + r.Host + "/" + feedId},
			Description: block.Message,
			Created:     time.UnixMilli(block.CreationTime),
		})
		feedinfo.Items = feedItems
	}
	rssFeed := (&feeds.Rss{Feed: feedinfo}).RssFeed()
	xmlRssFeeds := rssFeed.FeedXml()
	w.Header().Add("Content-Type", "application/rss+xml")

	xml.NewEncoder(w).Encode(xmlRssFeeds)
}

func enableCORS(router *mux.Router) {
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}).Methods(http.MethodOptions)
	router.Use(middlewareCors)
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			// Feeds are public, read-only and credential-free. A wildcard
			// origin is correct here, but it is mutually exclusive with
			// Allow-Credentials: true (browsers reject that combination), so we
			// do not set credentials.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Range")
			next.ServeHTTP(w, req)
		})
}

func newRouter() *mux.Router {
	r := mux.NewRouter()
	enableCORS(r)

	r.HandleFunc("/lookup/{name}", apiLookup)

	r.HandleFunc("/", empty)
	r.HandleFunc("/{feedId}/rss", serveRSS)
	r.HandleFunc("/{feedId}", serveFeed)

	r.HandleFunc("/api/{feedId}", apiFeed)
	r.HandleFunc("/api/{feedId}/block/{blockId}", apiFeedBlock)
	r.HandleFunc("/api/{feedId}/block/{blockId}/payload/{payloadOffset}", apiFeedBlockPayloadOffset)
	r.HandleFunc("/api/{feedId}/block/{blockId}/payload/{payloadOffset}/raw", apiFeedBlockPayloadOffsetRaw)

	r.HandleFunc("/api/{feedId}/offset/{offset}", apiFeedOffset)
	r.HandleFunc("/api/{feedId}/offset/{offset}/payload/{payloadOffset}", apiFeedOffsetPayloadOffset)
	r.HandleFunc("/api/{feedId}/offset/{offset}/payload/{payloadOffset}/raw", apiFeedOffsetPayloadOffsetRaw)

	return r
}

func main() {
	var port int

	flag.IntVar(&port, "port", 8091, "port")
	flag.StringVar(&repositoryPath, "path", "/var/feedchains", "path to repository")
	flag.Parse()

	err := os.MkdirAll(repositoryPath, 0700)
	if err != nil {
		log.Fatal(err)
	}

	r := newRouter()

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), handlers.CombinedLoggingHandler(os.Stdout, r))
	if err != nil {
		log.Fatal(err)
	}
}
