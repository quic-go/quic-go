package handshake

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var retryAEADDraft28, retryAEADDraft29 cipher.AEAD

func createRetryAEAD(key []byte) (cipher.AEAD, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(aes)
}

func init() {
	var err error
	retryAEADDraft28, err = createRetryAEAD([]byte{0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8, 0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30})
	if err != nil {
		panic(err)
	}
	retryAEADDraft29, err = createRetryAEAD([]byte{0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1})
	if err != nil {
		panic(err)
	}
}

var retryBuf bytes.Buffer
var retryMutex sync.Mutex
var retryNonceDraft28 = [12]byte{0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75}
var retryNonceDraft29 = [12]byte{0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c}

// GetRetryIntegrityTag calculates the integrity tag on a Retry packet
func GetRetryIntegrityTag(retry []byte, origDestConnID protocol.ConnectionID, v protocol.VersionNumber) *[16]byte {
	retryMutex.Lock()
	retryBuf.WriteByte(uint8(origDestConnID.Len()))
	retryBuf.Write(origDestConnID.Bytes())
	retryBuf.Write(retry)

	var tag [16]byte
	var sealed []byte
	if v == protocol.VersionDraft28 {
		sealed = retryAEADDraft28.Seal(tag[:0], retryNonceDraft28[:], nil, retryBuf.Bytes())
	} else {
		sealed = retryAEADDraft29.Seal(tag[:0], retryNonceDraft29[:], nil, retryBuf.Bytes())
	}
	if len(sealed) != 16 {
		panic(fmt.Sprintf("unexpected Retry integrity tag length: %d", len(sealed)))
	}
	retryBuf.Reset()
	retryMutex.Unlock()
	return &tag
}
