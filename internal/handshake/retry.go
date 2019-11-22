package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var retryAEAD cipher.AEAD

func init() {
	var key = [16]byte{0xf5, 0xed, 0x46, 0x42, 0xe0, 0xe4, 0xc8, 0xd8, 0x78, 0xbb, 0xbc, 0x8a, 0x82, 0x88, 0x21, 0xc9}

	aes, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	retryAEAD = aead
}

// GetRetryIntegrityTag calculates the integrity tag on a Retry packet
func GetRetryIntegrityTag(retry []byte, origDestConnID protocol.ConnectionID) *[16]byte {
	buf := bytes.NewBuffer(make([]byte, 0, 1+origDestConnID.Len()+len(retry)))
	buf.WriteByte(uint8(origDestConnID.Len()))
	buf.Write(origDestConnID.Bytes())
	buf.Write(retry)

	sealed := retryAEAD.Seal(nil, make([]byte, 12), []byte{}, buf.Bytes())
	if len(sealed) != 16 {
		panic(fmt.Sprintf("unexpected Retry integrity tag length: %d", len(sealed)))
	}
	var tag [16]byte
	copy(tag[:], sealed)
	return &tag
}
