package feedchain

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"
)

const SignatureSize = 64
const HeaderVersion = 1
const HeaderSize = 266

// Header field offsets within the HeaderSize-byte header. These are the single
// source of truth for the wire layout; ToBytes and NewHeaderFromBytes both read
// from them so the two can never drift. The layout is asserted by a test.
const (
	offVersion           = 0                                    // uint16
	offGenerationTime    = offVersion + 2                       // uint64
	offIndexOffset       = offGenerationTime + 8                // uint64
	offIndexLength       = offIndexOffset + 8                   // uint64
	offIndexChecksum     = offIndexLength + 8                   // [32]byte
	offIndexSignature    = offIndexChecksum + 32                // [64]byte
	offMetadataOffset    = offIndexSignature + 64               // uint64
	offMetadataLength    = offMetadataOffset + 8                // uint64
	offMetadataChecksum  = offMetadataLength + 8                // [32]byte
	offMetadataSignature = offMetadataChecksum + 32             // [64]byte
	offPublicKey         = offMetadataSignature + 64            // [32]byte
	headerEnd            = offPublicKey + ed25519.PublicKeySize // == HeaderSize
)

type Header struct {
	Version           uint16
	GenerationTime    uint64
	IndexOffset       uint64
	IndexLength       uint64
	IndexChecksum     [32]byte
	IndexSignature    [64]byte
	MetadataOffset    uint64
	MetadataLength    uint64
	MetadataChecksum  [32]byte
	MetadataSignature [64]byte
	PublicKey         ed25519.PublicKey
}

func NewHeader(stream *StreamWriter) *Header {
	return &Header{
		Version:        HeaderVersion,
		GenerationTime: uint64(time.Now().Unix()),
		PublicKey:      *stream.PublicKey,
	}
}

func NewHeaderFromBytes(buffer [266]byte) *Header {
	var IndexChecksum [32]byte
	var IndexSignature [64]byte
	var MetadataChecksum [32]byte
	var MetadataSignature [64]byte

	copy(IndexChecksum[:], buffer[offIndexChecksum:offIndexSignature])
	copy(IndexSignature[:], buffer[offIndexSignature:offMetadataOffset])
	copy(MetadataChecksum[:], buffer[offMetadataChecksum:offMetadataSignature])
	copy(MetadataSignature[:], buffer[offMetadataSignature:offPublicKey])

	return &Header{
		Version:           binary.BigEndian.Uint16(buffer[offVersion:offGenerationTime]),
		GenerationTime:    binary.BigEndian.Uint64(buffer[offGenerationTime:offIndexOffset]),
		IndexOffset:       binary.BigEndian.Uint64(buffer[offIndexOffset:offIndexLength]),
		IndexLength:       binary.BigEndian.Uint64(buffer[offIndexLength:offIndexChecksum]),
		IndexChecksum:     IndexChecksum,
		IndexSignature:    IndexSignature,
		MetadataOffset:    binary.BigEndian.Uint64(buffer[offMetadataOffset:offMetadataLength]),
		MetadataLength:    binary.BigEndian.Uint64(buffer[offMetadataLength:offMetadataChecksum]),
		MetadataChecksum:  MetadataChecksum,
		MetadataSignature: MetadataSignature,
		PublicKey:         buffer[offPublicKey:headerEnd],
	}
}

func (hdr *Header) ToBytes() [266]byte {
	var ret [266]byte

	binary.BigEndian.PutUint16(ret[offVersion:offGenerationTime], hdr.Version)
	binary.BigEndian.PutUint64(ret[offGenerationTime:offIndexOffset], hdr.GenerationTime)
	binary.BigEndian.PutUint64(ret[offIndexOffset:offIndexLength], hdr.IndexOffset)
	binary.BigEndian.PutUint64(ret[offIndexLength:offIndexChecksum], hdr.IndexLength)
	copy(ret[offIndexChecksum:offIndexSignature], hdr.IndexChecksum[:])
	copy(ret[offIndexSignature:offMetadataOffset], hdr.IndexSignature[:])
	binary.BigEndian.PutUint64(ret[offMetadataOffset:offMetadataLength], hdr.MetadataOffset)
	binary.BigEndian.PutUint64(ret[offMetadataLength:offMetadataChecksum], hdr.MetadataLength)
	copy(ret[offMetadataChecksum:offMetadataSignature], hdr.MetadataChecksum[:])
	copy(ret[offMetadataSignature:offPublicKey], hdr.MetadataSignature[:])
	copy(ret[offPublicKey:headerEnd], hdr.PublicKey[:])
	return ret
}
