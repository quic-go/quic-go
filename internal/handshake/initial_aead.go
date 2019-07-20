package handshake

import (
	"crypto"
	"crypto/aes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/marten-seemann/qtls"
)

var quicVersion1Salt = []byte{0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a}

// NewInitialAEAD creates a new AEAD for Initial encryption / decryption.
func NewInitialAEAD(connID protocol.ConnectionID, pers protocol.Perspective) (LongHeaderSealer, LongHeaderOpener, error) {
	clientSecret, serverSecret := computeSecrets(connID)
	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}
	myKey, myHPKey, myIV := computeInitialKeyAndIV(mySecret)
	otherKey, otherHPKey, otherIV := computeInitialKeyAndIV(otherSecret)

	encrypter := qtls.AEADAESGCMTLS13(myKey, myIV)
	hpEncrypter, err := aes.NewCipher(myHPKey)
	if err != nil {
		return nil, nil, err
	}
	decrypter := qtls.AEADAESGCMTLS13(otherKey, otherIV)
	hpDecrypter, err := aes.NewCipher(otherHPKey)
	if err != nil {
		return nil, nil, err
	}
	return newLongHeaderSealer(encrypter, hpEncrypter), newLongHeaderOpener(decrypter, hpDecrypter), nil
}

func computeSecrets(connID protocol.ConnectionID) (clientSecret, serverSecret []byte) {
	initialSecret := qtls.HkdfExtract(crypto.SHA256, connID, quicVersion1Salt)
	clientSecret = qtls.HkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	serverSecret = qtls.HkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "server in", crypto.SHA256.Size())
	return
}

func computeInitialKeyAndIV(secret []byte) (key, hpKey, iv []byte) {
	key = qtls.HkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	hpKey = qtls.HkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	iv = qtls.HkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	return
}
