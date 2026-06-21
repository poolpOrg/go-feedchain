package feedchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"
)

type StreamReader struct {
	rd         io.ReadSeekCloser
	dataOffset int64

	CreationTime time.Time
	Blocks       []*Block
	Index        *Index
	Metadata     *Metadata
	PublicKey    *ed25519.PublicKey

	HeaderChecksum  string
	HeaderSignature string

	IndexChecksum  string
	IndexSignature string

	MetadataChecksum  string
	MetadataSignature string

	cursor uint64
}

func NewReaderFromFile(pathname string) (*StreamReader, error) {
	fp, err := os.OpenFile(pathname, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return NewReader(fp)
}

func NewReaderFromURL(url string) (*StreamReader, error) {
	hr, err := NewHTTPReader(url)
	if err != nil {
		return nil, err
	}
	return NewReader(hr)
}

func NewReader(rd io.ReadSeekCloser) (*StreamReader, error) {
	// read header signature
	var headerSignature [64]byte
	if _, err := io.ReadFull(rd, headerSignature[:]); err != nil {
		return nil, err
	}

	var headerBuf [HeaderSize]byte
	if _, err := io.ReadFull(rd, headerBuf[:]); err != nil {
		return nil, err
	}
	header := NewHeaderFromBytes(headerBuf)
	headerChecksum := sha256.Sum256(headerBuf[:])

	if !ed25519.Verify(header.PublicKey, headerChecksum[:], headerSignature[:]) {
		return nil, fmt.Errorf("header signature verification failed")
	}

	_, err := rd.Seek(SignatureSize+HeaderSize+int64(header.IndexOffset), 0)
	if err != nil {
		return nil, err
	}
	indexBuf := make([]byte, header.IndexLength)
	if _, err := io.ReadFull(rd, indexBuf); err != nil {
		return nil, err
	}
	index := NewIndexFromBytes(indexBuf)
	indexChecksum := sha256.Sum256(indexBuf[:])

	if !bytes.Equal(indexChecksum[:], header.IndexChecksum[:]) {
		return nil, fmt.Errorf("index checksum verification failed")
	}

	_, err = rd.Seek(SignatureSize+HeaderSize+int64(header.MetadataOffset), 0)
	if err != nil {
		return nil, err
	}
	metadataBuf := make([]byte, header.MetadataLength)
	if _, err := io.ReadFull(rd, metadataBuf); err != nil {
		return nil, err
	}
	metadata := NewMetadataFromBytes(metadataBuf)
	metadataChecksum := sha256.Sum256(metadataBuf[:])

	if !bytes.Equal(metadataChecksum[:], header.MetadataChecksum[:]) {
		return nil, fmt.Errorf("metadata checksum verification failed")
	}

	stream := &StreamReader{
		Index:      index,
		Metadata:   metadata,
		PublicKey:  &header.PublicKey,
		rd:         rd,
		dataOffset: int64(SignatureSize + HeaderSize),

		HeaderChecksum:  base64.RawURLEncoding.EncodeToString(headerChecksum[:]),
		HeaderSignature: base64.RawURLEncoding.EncodeToString(headerSignature[:]),

		IndexChecksum:  base64.RawURLEncoding.EncodeToString(indexChecksum[:]),
		IndexSignature: base64.RawURLEncoding.EncodeToString(header.IndexSignature[:]),

		MetadataChecksum:  base64.RawURLEncoding.EncodeToString(metadataChecksum[:]),
		MetadataSignature: base64.RawURLEncoding.EncodeToString(header.MetadataSignature[:]),

		cursor: 0,
	}

	return stream, nil
}

func (stream *StreamReader) ID() string {
	return base64.RawURLEncoding.EncodeToString(*stream.PublicKey)
}

func (stream *StreamReader) Verify(block *Block) bool {
	checksum := sha256.Sum256(block.ToBytes())
	for _, record := range stream.Index.Records {
		if base64.RawURLEncoding.EncodeToString(checksum[:]) == record.BlockChecksum {
			signature, err := base64.RawURLEncoding.DecodeString(record.BlockSignature)
			if err != nil {
				continue
			}
			return ed25519.Verify(*stream.PublicKey, checksum[:], signature)
		}
	}
	return false
}

func (stream *StreamReader) Offset(offset uint64) (*Block, error) {
	if offset >= uint64(len(stream.Index.Records)) {
		return nil, io.EOF
	}

	record := stream.Index.Records[offset]

	_, err := stream.rd.Seek(int64(record.BlockOffset)+stream.dataOffset, 0)
	if err != nil {
		return nil, err
	}

	blockBuffer := make([]byte, record.BlockLen)
	if _, err := io.ReadFull(stream.rd, blockBuffer); err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(blockBuffer)

	if base64.RawURLEncoding.EncodeToString(checksum[:]) != record.BlockChecksum {
		return nil, fmt.Errorf("chunk mismatches index checksum")
	}

	block, err := NewBlockFromBytes(blockBuffer)
	if err != nil {
		return nil, err
	}
	if !stream.Verify(block) {
		return nil, fmt.Errorf("chunk mismatches index signature")
	}

	return block, nil
}

func (stream *StreamReader) Size() uint64 {
	return uint64(len(stream.Index.Records))
}

func (stream *StreamReader) Next() (*Block, error) {
	block, err := stream.Offset(stream.cursor)
	if err != nil {
		return nil, err
	}
	stream.cursor++
	return block, nil
}

func (stream *StreamReader) Close() error {
	return stream.rd.Close()
}
