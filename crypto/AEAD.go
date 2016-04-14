package crypto

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
)

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext io.Reader) (*bytes.Reader, error)
	Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte)
}
