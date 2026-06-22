package feedchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Payload struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
}

type Block struct {
	CreationTime int64     `json:"creation_time"`
	Message      string    `json:"message"`
	Payload      []Payload `json:"payloads"`
	Thread       string    `json:"thread"`
	Parent       string    `json:"parent"`
}

func NewBlockFromBytes(buffer []byte) (*Block, error) {
	var block Block
	if err := json.Unmarshal(buffer, &block); err != nil {
		return nil, fmt.Errorf("block.NewBlockFromBytes: %w", err)
	}
	return &block, nil
}

func (block *Block) ToBytes() []byte {
	serialized, err := json.Marshal(block)
	if err != nil {
		panic("block.ToBytes")
	}
	return serialized
}

// ID returns the block's identifier: the hex-encoded sha256 of its serialized
// bytes (64 hex characters).
func (block *Block) ID() string {
	checksum := sha256.Sum256(block.ToBytes())
	return hex.EncodeToString(checksum[:])
}
