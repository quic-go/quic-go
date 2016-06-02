package crypto

import (
	"encoding/binary"
	"errors"

	"github.com/lucas-clemente/fnv128a"
	"github.com/lucas-clemente/quic-go/protocol"
)

// NullAEAD handles not-yet encrypted packets
type NullAEAD struct{}

var _ AEAD = &NullAEAD{}

// Open and verify the ciphertext
func (NullAEAD) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 12 bytes long")
	}

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(ciphertext[12:])
	testHigh, testLow := hash.Sum128()

	low := binary.LittleEndian.Uint64(ciphertext)
	high := binary.LittleEndian.Uint32(ciphertext[8:])

	if uint32(testHigh&0xffffffff) != high || testLow != low {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return ciphertext[12:], nil
}

// Seal writes hash and ciphertext to the buffer
func (NullAEAD) Seal(packetNumber protocol.PacketNumber, associatedData []byte, plaintext []byte) []byte {
	res := make([]byte, 12+len(plaintext))

	hash := fnv128a.New()
	hash.Write(associatedData)
	hash.Write(plaintext)
	high, low := hash.Sum128()

	binary.LittleEndian.PutUint64(res, low)
	binary.LittleEndian.PutUint32(res[8:], uint32(high))
	copy(res[12:], plaintext)
	return res
}
