package crypto

import (
	"encoding/binary"
	"errors"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type nullAEADFNV64a struct{}

var _ AEAD = &nullAEADFNV64a{}

// Open and verify the ciphertext
func (n *nullAEADFNV64a) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	if len(src) < 8 {
		return nil, errors.New("NullAEAD: ciphertext cannot be less than 8 bytes long")
	}
	data := src[:len(src)-8]

	hash := fnv.New64a()
	hash.Write(associatedData)
	hash.Write(data)

	if hash.Sum64() != binary.BigEndian.Uint64(src[len(src)-8:]) {
		return nil, errors.New("NullAEAD: failed to authenticate received data")
	}
	return data, nil
}

// Seal writes hash and ciphertext to the buffer
func (n *nullAEADFNV64a) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if cap(dst) < 8+len(src) {
		dst = make([]byte, 8+len(src))
	} else {
		dst = dst[:8+len(src)]
	}

	hash := fnv.New64a()
	hash.Write(associatedData)
	hash.Write(src)
	copy(dst, src)
	binary.BigEndian.PutUint64(dst[len(src):], hash.Sum64())
	return dst
}

func (n *nullAEADFNV64a) Overhead() int {
	return 8
}
