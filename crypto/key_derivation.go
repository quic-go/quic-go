package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeysAESGCM derives the client and server keys and creates a matching AES-GCM instance
func DeriveKeysAESGCM(sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte) (AEAD, error) {
	var info bytes.Buffer
	info.Write([]byte("QUIC key expansion\x00"))
	utils.WriteUint64(&info, uint64(connID))
	info.Write(chlo)
	info.Write(scfg)

	r := hkdf.New(sha256.New, sharedSecret, nonces, info.Bytes())

	otherKey := make([]byte, 16)
	myKey := make([]byte, 16)
	otherIV := make([]byte, 4)
	myIV := make([]byte, 4)

	if _, err := io.ReadFull(r, otherKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, myKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, otherIV); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, myIV); err != nil {
		return nil, err
	}

	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}
