package feedchain

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type indexRecord struct {
	CreationTime   int64  `json:"creation_time"`
	BlockOffset    uint64 `json:"offset"`
	BlockLen       uint64 `json:"length"`
	BlockChecksum  string `json:"digest"`
	BlockSignature string `json:"signature"`
}

type Index struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Picture     string `json:"picture"`

	Records    []indexRecord       `json:"records"`
	Hashtags   map[string][]string `json:"hashtags"`
	Mentions   map[string][]string `json:"mentions"`
	References map[string][]string `json:"references"`
	Threads    map[string][]string `json:"threads"`
}

func NewIndex() *Index {
	return &Index{
		Records:    make([]indexRecord, 0),
		Hashtags:   make(map[string][]string),
		Mentions:   make(map[string][]string),
		References: make(map[string][]string),
		Threads:    make(map[string][]string),
	}
}

func NewIndexFromBytes(buffer []byte) *Index {
	var index Index
	err := json.Unmarshal(buffer, &index)
	if err != nil {
		panic("index.NewIndexFromBytes")
	}
	return &index
}

func (index *Index) ToBytes() []byte {
	serialized, err := json.Marshal(index)
	if err != nil {
		panic("index.ToBytes")
	}
	return serialized
}

func (index *Index) Record(creationTime int64, blockLen uint64, blockChecksum [32]byte, blockSignature [64]byte) {
	blockOffset := uint64(0)
	if len(index.Records) != 0 {
		blockOffset = index.Records[len(index.Records)-1].BlockOffset + index.Records[len(index.Records)-1].BlockLen
	}
	index.Records = append(index.Records, indexRecord{
		CreationTime:   creationTime,
		BlockOffset:    blockOffset,
		BlockLen:       blockLen,
		BlockChecksum:  base64.RawURLEncoding.EncodeToString(blockChecksum[:]),
		BlockSignature: base64.RawURLEncoding.EncodeToString(blockSignature[:]),
	})
}

func (index *Index) Tag(hashtag string, blockChecksum [32]byte) {
	if _, exists := index.Hashtags[hashtag]; !exists {
		index.Hashtags[hashtag] = make([]string, 0)
	}
	index.Hashtags[hashtag] = append(index.Hashtags[hashtag], base64.RawURLEncoding.EncodeToString(blockChecksum[:]))
}

func (index *Index) Mention(mention string, blockChecksum [32]byte) {
	if _, exists := index.Mentions[mention]; !exists {
		index.References[mention] = make([]string, 0)
	}
	index.References[mention] = append(index.References[mention], base64.RawURLEncoding.EncodeToString(blockChecksum[:]))
}

func (index *Index) Reference(ref string, blockChecksum [32]byte) {
	if _, exists := index.References[ref]; !exists {
		index.References[ref] = make([]string, 0)
	}
	index.References[ref] = append(index.References[ref], base64.RawURLEncoding.EncodeToString(blockChecksum[:]))
}

func (index *Index) Thread(thread string, blockChecksum [32]byte) {
	if _, exists := index.Threads[thread]; !exists {
		index.Threads[thread] = make([]string, 0)
	}
	index.Threads[thread] = append(index.Threads[thread], base64.RawURLEncoding.EncodeToString(blockChecksum[:]))
}

func (index *Index) Search(term string) []string {
	if strings.HasPrefix(term, "#") {
		if blocks, exists := index.Hashtags[term[1:]]; !exists {
			return nil
		} else {
			return blocks
		}
	}

	if strings.HasPrefix(term, "@") {
		if blocks, exists := index.References[term[1:]]; !exists {
			return nil
		} else {
			return blocks
		}
	}

	return nil
}
