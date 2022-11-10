package feedchain

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"
)

const SignatureSize = 64
const HeaderVersion = 1
const HeaderSize = 154

type Header struct {
	Version        uint16
	GenerationTime uint64
	IndexOffset    uint64
	IndexLength    uint64
	IndexChecksum  [32]byte
	IndexSignature [64]byte
	PublicKey      ed25519.PublicKey
}

func NewHeader(stream *StreamWriter) *Header {
	return &Header{
		Version:        HeaderVersion,
		GenerationTime: uint64(time.Now().Unix()),
		PublicKey:      *stream.PublicKey,
	}
}

func NewHeaderFromBytes(buffer [154]byte) *Header {
	var IndexChecksum [32]byte
	var IndexSignature [64]byte

	copy(IndexChecksum[:], buffer[26:58])
	copy(IndexSignature[:], buffer[58:122])
	return &Header{
		Version:        binary.BigEndian.Uint16(buffer[0:2]),
		GenerationTime: binary.BigEndian.Uint64(buffer[2:10]),
		IndexOffset:    binary.BigEndian.Uint64(buffer[10:18]),
		IndexLength:    binary.BigEndian.Uint64(buffer[18:26]),
		IndexChecksum:  IndexChecksum,
		IndexSignature: IndexSignature,
		PublicKey:      buffer[122:154],
	}
}

func (hdr *Header) ToBytes() [154]byte {
	var ret [154]byte

	binary.BigEndian.PutUint16(ret[0:2], hdr.Version)
	binary.BigEndian.PutUint64(ret[2:10], hdr.GenerationTime)
	binary.BigEndian.PutUint64(ret[10:18], hdr.IndexOffset)
	binary.BigEndian.PutUint64(ret[18:26], hdr.IndexLength)
	copy(ret[26:58], hdr.IndexChecksum[:])
	copy(ret[58:122], hdr.IndexSignature[:])
	copy(ret[122:154], hdr.PublicKey[:])
	return ret
}
