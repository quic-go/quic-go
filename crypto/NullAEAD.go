package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// NullAEAD handles not-yet encrypted packets
type NullAEAD struct{}

var _ AEAD = &NullAEAD{}

// Open and verify the ciphertext
func (*NullAEAD) Open(packetNumber protocol.PacketNumber, associatedData []byte, r io.Reader) (*bytes.Reader, error) {
	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 12 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 12 bytes long")
	}

	hash := New128a()
	hash.Write(associatedData)
	hash.Write(ciphertext[12:])
	testHigh, testLow := hash.Sum128()

	low := binary.LittleEndian.Uint64(ciphertext)
	high := binary.LittleEndian.Uint32(ciphertext[8:])

	if uint32(testHigh&0xffffffff) != high || testLow != low {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return bytes.NewReader(ciphertext[12:]), nil
}

// Seal writes hash and ciphertext to the buffer
func (*NullAEAD) Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte) {
	hash := New128a()
	hash.Write(associatedData)
	hash.Write(plaintext)
	high, low := hash.Sum128()

	utils.WriteUint64(b, low)
	utils.WriteUint32(b, uint32(high))
	b.Write(plaintext)
}
