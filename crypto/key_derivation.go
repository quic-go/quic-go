package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeysChacha20 derives the client and server keys and creates a matching chacha20poly1305 instance
func DeriveKeysChacha20(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte) (AEAD, error) {
	var info bytes.Buffer
	if forwardSecure {
		info.Write([]byte("QUIC forward secure key expansion\x00"))
	} else {
		info.Write([]byte("QUIC key expansion\x00"))
	}
	utils.WriteUint64(&info, uint64(connID))
	info.Write(chlo)
	info.Write(scfg)
	info.Write(cert)

	r := hkdf.New(sha256.New, sharedSecret, nonces, info.Bytes())

	otherKey := make([]byte, 32)
	myKey := make([]byte, 32)
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

	return NewAEADChacha20Poly1305(otherKey, myKey, otherIV, myIV)
}
