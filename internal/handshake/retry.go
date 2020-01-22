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
	var key = [16]byte{0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30}

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
var retryNonce = [12]byte{0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75}

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
