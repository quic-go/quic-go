package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/protocol"
)

type aeadAESGCM struct {
	otherIV   []byte
	myIV      []byte
	encrypter cipher.AEAD
	decrypter cipher.AEAD
}

// NewAEADAESGCM creates a AEAD using AES-GCM
func NewAEADAESGCM(otherKey []byte, myKey []byte, otherIV []byte, myIV []byte) (AEAD, error) {
	if len(myKey) != 16 || len(otherKey) != 16 || len(myIV) != 4 || len(otherIV) != 4 {
		return nil, errors.New("AES-GCM: expected 16-byte keys and 4-byte IVs")
	}
	encCipher, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, err
	}
	encrypter, err := cipher.NewGCM(encCipher)
	if err != nil {
		return nil, err
	}
	decCipher, err := aes.NewCipher(otherKey)
	if err != nil {
		return nil, err
	}
	decrypter, err := cipher.NewGCM(decCipher)
	if err != nil {
		return nil, err
	}
	return &aeadAESGCM{
		otherIV:   otherIV,
		myIV:      myIV,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (aead *aeadAESGCM) Open(packetNumber protocol.PacketNumber, associatedData []byte, r io.Reader) (*bytes.Reader, error) {
	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.decrypter.Open(nil, makeNonce(aead.otherIV, packetNumber), ciphertext, associatedData)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(plaintext), nil
}

func (aead *aeadAESGCM) Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte) {
	ciphertext := aead.encrypter.Seal(nil, makeNonce(aead.myIV, packetNumber), plaintext, associatedData)
	b.Write(ciphertext)
}

func makeNonce(iv []byte, packetNumber protocol.PacketNumber) []byte {
	res := make([]byte, 12)
	copy(res[0:4], iv)
	binary.LittleEndian.PutUint64(res[4:12], uint64(packetNumber))
	return res
}
