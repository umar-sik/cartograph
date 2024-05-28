package http

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
)

// DecodeGzip returns a decoded version of the given gzip-encoded contents.
func DecodeGzip(contents []byte) ([]byte, error) {
	br := bytes.NewReader(contents)
	decompressor, newReaderErr := gzip.NewReader(br)
	if newReaderErr != nil {
		return nil, fmt.Errorf("unable to create new gzip reader to read contents: %w", newReaderErr)
	}
	decoded, decodeErr := io.ReadAll(decompressor)
	if decodeErr != nil {
		return nil, fmt.Errorf("unable to decode gzip-encoded contents: %w", decodeErr)
	}
	return decoded, nil
}

// DecodeBrotli returns a decoded version of the given brotli-encoded contents
func DecodeBrotli(contents []byte) ([]byte, error) {
	br := bytes.NewReader(contents)
	decompressor := brotli.NewReader(br)
	decoded, decodeErr := io.ReadAll(decompressor)
	if decodeErr != nil {
		return nil, fmt.Errorf("unable to decode brotli-encoded contents: %w", decodeErr)
	}
	return decoded, nil
}

// DecodeDeflate returns a decoded version of the given deflate-encoded contents
func DecodeDeflate(contents []byte) ([]byte, error) {
	br := bytes.NewReader(contents)
	decompressor := flate.NewReader(br)
	decoded, decodeErr := io.ReadAll(decompressor)
	if decodeErr != nil {
		return nil, fmt.Errorf("unable to decode deflate-encoded contents: %w", decodeErr)
	}
	return decoded, nil
}
