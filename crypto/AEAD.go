package crypto

import "github.com/lucas-clemente/quic-go/protocol"

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext []byte) ([]byte, error)
	Seal(packetNumber protocol.PacketNumber, associatedData []byte, plaintext []byte) []byte
}
