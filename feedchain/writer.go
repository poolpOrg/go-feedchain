package feedchain

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type StreamWriter struct {
	privateKey *ed25519.PrivateKey
	key        []byte

	Blocks    []*Block
	Index     *Index
	Metadata  *Metadata
	PublicKey *ed25519.PublicKey
	Signature []byte
}

func parseTags(title string) []string {
	re := regexp.MustCompile("#\\S+")
	extractTags := re.FindAllString(title, -1)
	for i, tag := range extractTags {
		extractTags[i] = strings.TrimLeft(tag, "#")
	}

	tags := make(map[string]bool)
	for _, tag := range extractTags {
		tags[tag] = true
	}

	ret := make([]string, 0)
	for tag, _ := range tags {
		ret = append(ret, tag)
	}
	return ret
}

func parseRefs(title string) []string {
	re := regexp.MustCompile("@\\S+")
	extractRefs := re.FindAllString(title, -1)
	for i, tag := range extractRefs {
		extractRefs[i] = strings.TrimLeft(tag, "@")
	}

	tags := make(map[string]bool)
	for _, tag := range extractRefs {
		tags[tag] = true
	}

	ret := make([]string, 0)
	for tag, _ := range tags {
		ret = append(ret, tag)
	}
	return ret
}

func Init(privateKey ed25519.PrivateKey) (*StreamWriter, error) {
	stream := &StreamWriter{
		Blocks:   make([]*Block, 0),
		Index:    NewIndex(),
		Metadata: NewMetadata(),
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	stream.privateKey = &privateKey
	stream.PublicKey = &publicKey
	return stream, nil
}

func NewWriter(privateKey ed25519.PrivateKey, pathname string) (*StreamWriter, error) {
	f, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// read header signature
	var headerSignature [64]byte
	f.Read(headerSignature[:])

	// read header
	var headerBuf [HeaderSize]byte
	f.Read(headerBuf[:])
	header := NewHeaderFromBytes(headerBuf)
	headerChecksum := sha256.Sum256(headerBuf[:])

	if !ed25519.Verify(header.PublicKey, headerChecksum[:], headerSignature[:]) {
		return nil, fmt.Errorf("header signature verification failed")
	}

	_, err = f.Seek(SignatureSize+HeaderSize+int64(header.IndexOffset), 0)
	if err != nil {
		return nil, err
	}
	indexBuf := make([]byte, header.IndexLength)
	f.Read(indexBuf)
	indexChecksum := sha256.Sum256(indexBuf[:])

	if !bytes.Equal(indexChecksum[:], header.IndexChecksum[:]) {
		return nil, fmt.Errorf("index checksum verification failed")
	}

	_, err = f.Seek(SignatureSize+HeaderSize+int64(header.MetadataOffset), 0)
	if err != nil {
		return nil, err
	}
	metadataBuf := make([]byte, header.MetadataLength)
	f.Read(metadataBuf)
	metadata := NewMetadataFromBytes(metadataBuf)
	metadataChecksum := sha256.Sum256(metadataBuf[:])

	if !bytes.Equal(metadataChecksum[:], header.MetadataChecksum[:]) {
		return nil, fmt.Errorf("metadata checksum verification failed")
	}

	_, err = f.Seek(SignatureSize+HeaderSize, 0)
	if err != nil {
		return nil, err
	}

	stream := &StreamWriter{
		Blocks:     make([]*Block, 0),
		Index:      NewIndexFromBytes(indexBuf),
		Metadata:   metadata,
		PublicKey:  &header.PublicKey,
		privateKey: (*ed25519.PrivateKey)(&privateKey),
		Signature:  header.IndexSignature[:],
	}

	for _, record := range stream.Index.Records {
		blockBuffer := make([]byte, record.BlockLen)
		f.Read(blockBuffer)
		checksum := sha256.Sum256(blockBuffer)

		if base64.RawURLEncoding.EncodeToString(checksum[:]) != record.BlockChecksum {
			return nil, fmt.Errorf("chunk mismatches index checksum")
		}

		block := NewBlockFromBytes(blockBuffer)
		if !stream.Verify(block) {
			return nil, fmt.Errorf("chunk mismatches index signature")
		}
		stream.Blocks = append(stream.Blocks, block)

	}

	return stream, nil
}

func (stream *StreamWriter) ID() string {
	return base64.RawURLEncoding.EncodeToString(*stream.PublicKey)
}

func (stream *StreamWriter) Verify(block *Block) bool {
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

func (stream *StreamWriter) Writeable() bool {
	return stream.privateKey != nil
}

func (stream *StreamWriter) Append(title string) error {
	var parentChecksum [32]byte
	if len(stream.Index.Records) == 0 {
		parentChecksum = sha256.Sum256(*stream.PublicKey)
	} else {
		lastBlock := stream.Blocks[len(stream.Blocks)-1]
		parentChecksum = sha256.Sum256(lastBlock.ToBytes())
	}

	now := time.Now().UnixMilli()
	block := &Block{
		Message:      title,
		CreationTime: now,
		Parent:       base64.RawStdEncoding.EncodeToString(parentChecksum[:]),
	}
	stream.Blocks = append(stream.Blocks, block)

	checksum := sha256.Sum256(block.ToBytes())
	signature := ed25519.Sign(*stream.privateKey, checksum[:])
	var signature64bytes [64]byte
	copy(signature64bytes[:], signature)
	stream.Index.Record(now, uint64(len(block.ToBytes())), checksum, signature64bytes)

	for _, tag := range parseTags(title) {
		stream.Index.Tag(tag, checksum)
	}

	for _, ref := range parseRefs(title) {
		stream.Index.Reference(ref, checksum)
	}

	return nil
}

func (stream *StreamWriter) Commit(pathname string) error {
	indexBytes := stream.Index.ToBytes()
	indexChecksum := sha256.Sum256(indexBytes)
	indexSignature := ed25519.Sign(*stream.privateKey, indexChecksum[:])
	var indexSignature64 [64]byte
	copy(indexSignature64[:], indexSignature)

	indexOffset := uint64(0)
	for _, entry := range stream.Index.Records {
		indexOffset += entry.BlockLen
	}

	metadataBytes := stream.Metadata.ToBytes()
	metadataChecksum := sha256.Sum256(metadataBytes)
	metadataSignature := ed25519.Sign(*stream.privateKey, metadataChecksum[:])
	var metadataSignature64 [64]byte
	copy(metadataSignature64[:], metadataSignature)

	metadataOffset := indexOffset + uint64(len(indexBytes))

	header := NewHeader(stream)
	header.IndexOffset = indexOffset
	header.IndexLength = uint64(len(indexBytes))
	header.IndexChecksum = indexChecksum
	header.IndexSignature = indexSignature64
	header.MetadataOffset = metadataOffset
	header.MetadataLength = uint64(len(metadataBytes))
	header.MetadataChecksum = metadataChecksum
	header.MetadataSignature = metadataSignature64

	headerBytes := header.ToBytes()
	headerChecksum := sha256.Sum256(headerBytes[:])
	headerSignature := ed25519.Sign(*stream.privateKey, headerChecksum[:])

	f, err := os.Create(pathname)
	if err != nil {
		return err
	}
	defer f.Close()

	wr := bufio.NewWriter(f)

	_, err = wr.Write(headerSignature[:])
	if err != nil {
		return err
	}

	_, err = wr.Write(headerBytes[:])
	if err != nil {
		return err
	}

	for _, block := range stream.Blocks {
		_, err = wr.Write(block.ToBytes())
		if err != nil {
			return err
		}
	}

	_, err = wr.Write(indexBytes)
	if err != nil {
		return err
	}

	_, err = wr.Write(metadataBytes)
	if err != nil {
		return err
	}

	wr.Flush()
	return nil
}
