package feedchain

import (
	"encoding/json"
)

type Metadata struct {
	Picture     string `json:"picture"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Location    string `json:"location"`
}

func NewMetadata() *Metadata {
	return &Metadata{}
}

func NewMetadataFromBytes(buffer []byte) *Metadata {
	var metadata Metadata
	err := json.Unmarshal(buffer, &metadata)
	if err != nil {
		panic("metadata.NewMetadataFromBytes")
	}
	return &metadata
}

func (metadata *Metadata) ToBytes() []byte {
	serialized, err := json.Marshal(metadata)
	if err != nil {
		panic("metadata.ToBytes")
	}
	return serialized
}

func (metadata *Metadata) Set(key string, value string) {

}
