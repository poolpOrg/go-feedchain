package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	Origin    string `json:"origin"`
	Size      int    `json:"length"`
	Checksum  string `json:"digest"`
	Signature string `json:"signature"`
}

var repositoryPath string

func serveFeed(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]

	if r.Method == "HEAD" || r.Method == "GET" {
		file, err := os.Open(repositoryPath + "/" + feedId)
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
		file, err := ioutil.TempFile("/tmp", "feedchain.")
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(file.Name())

		_, err = io.Copy(file, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		file.Close()

		feed, err := feedchain.NewReaderFromFile(file.Name())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if feed.ID() != feedId {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		err = os.Rename(file.Name(), repositoryPath+"/"+feed.ID())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		feed.Close()
	}
}

func apiFeed(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	feedId := vars["feedId"]

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

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

	feed, err := feedchain.NewReaderFromFile(repositoryPath + "/" + feedId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer feed.Close()

	if feed.ID() != feedId {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

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
				Origin:    r.Host,
				Size:      len(feed.Index.Records),
				PublicKey: feed.ID(),
				Checksum:  feed.HeaderChecksum,
				Signature: feed.HeaderSignature,
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

func enableCORS(router *mux.Router) {
	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}).Methods(http.MethodOptions)
	router.Use(middlewareCors)
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			next.ServeHTTP(w, req)
		})
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

	r := mux.NewRouter()
	enableCORS(r)

	r.HandleFunc("/", apiFeeds)
	r.HandleFunc("/{feedId}", serveFeed)

	r.HandleFunc("/feed/{feedId}", apiFeed)
	r.HandleFunc("/feed/{feedId}/block/{blockId}", apiFeedBlock)
	r.HandleFunc("/feed/{feedId}/block/{blockId}/payload/{payloadOffset}", apiFeedBlockPayloadOffset)
	r.HandleFunc("/feed/{feedId}/block/{blockId}/payload/{payloadOffset}/raw", apiFeedBlockPayloadOffsetRaw)

	r.HandleFunc("/feed/{feedId}/offset/{offset}", apiFeedOffset)
	r.HandleFunc("/feed/{feedId}/offset/{offset}/payload/{payloadOffset}", apiFeedOffsetPayloadOffset)
	r.HandleFunc("/feed/{feedId}/offset/{offset}/payload/{payloadOffset}/raw", apiFeedOffsetPayloadOffsetRaw)

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), handlers.CombinedLoggingHandler(os.Stdout, r))
	if err != nil {
		log.Fatal(err)
	}
}
