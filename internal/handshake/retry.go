package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var retryAEAD cipher.AEAD

func init() {
	var key = [16]byte{0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1}

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

var retryBuf bytes.Buffer
var retryMutex sync.Mutex
var retryNonce = [12]byte{0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c}

// GetRetryIntegrityTag calculates the integrity tag on a Retry packet
func GetRetryIntegrityTag(retry []byte, origDestConnID protocol.ConnectionID) *[16]byte {
	retryMutex.Lock()
	retryBuf.WriteByte(uint8(origDestConnID.Len()))
	retryBuf.Write(origDestConnID.Bytes())
	retryBuf.Write(retry)

	var tag [16]byte
	sealed := retryAEAD.Seal(tag[:0], retryNonce[:], nil, retryBuf.Bytes())
	if len(sealed) != 16 {
		panic(fmt.Sprintf("unexpected Retry integrity tag length: %d", len(sealed)))
	}
	retryBuf.Reset()
	retryMutex.Unlock()
	return &tag
}
