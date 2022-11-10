package feedchain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

type Payload struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
}

type Block struct {
	CreationTime time.Time `json:"creation_time"`
	Message      string    `json:"message"`
	Payload      []Payload `json:"payloads"`
	Thread       string    `json:"thread"`
	Parent       string    `json:"parent"`
}

func NewBlockFromBytes(buffer []byte) *Block {
	var block Block
	err := json.Unmarshal(buffer, &block)
	if err != nil {
		panic("block.NewBlockFromBytes")
	}
	return &block
}

func (block *Block) ToBytes() []byte {
	serialized, err := json.Marshal(block)
	if err != nil {
		panic("block.ToBytes")
	}
	return serialized
}

func (block *Block) ID() string {
	checksum := sha256.Sum256(block.ToBytes())
	return fmt.Sprintf("%016x", checksum)
}
