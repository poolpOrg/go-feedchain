package feedchain

import (
	"encoding/json"
	"fmt"
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

// Set assigns value to the named metadata field. It returns an error for an
// unknown key rather than silently doing nothing.
func (metadata *Metadata) Set(key string, value string) error {
	switch key {
	case "picture":
		metadata.Picture = value
	case "name":
		metadata.Name = value
	case "description":
		metadata.Description = value
	case "location":
		metadata.Location = value
	default:
		return fmt.Errorf("metadata.Set: unknown key %q", key)
	}
	return nil
}
