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
	PublicKey    *ed25519.PublicKey
	Signature    []byte
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
	rd.Read(headerSignature[:])

	var headerBuf [HeaderSize]byte
	rd.Read(headerBuf[:])
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
	rd.Read(indexBuf)
	index := NewIndexFromBytes(indexBuf)
	indexChecksum := sha256.Sum256(indexBuf[:])

	if !bytes.Equal(indexChecksum[:], header.IndexChecksum[:]) {
		return nil, fmt.Errorf("index checksum verification failed")
	}

	stream := &StreamReader{
		Index:      index,
		PublicKey:  &header.PublicKey,
		rd:         rd,
		dataOffset: int64(SignatureSize + HeaderSize),
		Signature:  header.IndexSignature[:],
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
	_, err = stream.rd.Read(blockBuffer)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(blockBuffer)

	if base64.RawURLEncoding.EncodeToString(checksum[:]) != record.BlockChecksum {
		return nil, fmt.Errorf("chunk mismatches index checksum")
	}

	block := NewBlockFromBytes(blockBuffer)
	if !stream.Verify(block) {
		return nil, fmt.Errorf("chunk mismatches index signature")
	}

	return block, nil
}

func (stream *StreamReader) Size() uint64 {
	return uint64(len(stream.Index.Records))
}

func (stream *StreamReader) Close() error {
	return stream.rd.Close()
}