package feedchain

import (
	"encoding/json"
)

type Metadata struct {
	Banner      string `json:"banner"`
	Picture     string `json:"picture"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Origin      string `json:"origin"`
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
