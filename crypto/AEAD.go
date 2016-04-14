package crypto

import (
	"bytes"
	"io"
)

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(packetNumber uint64, associatedData []byte, ciphertext io.Reader) (*bytes.Reader, error)
	Seal(packetNumber uint64, b *bytes.Buffer, associatedData []byte, plaintext []byte)
}
