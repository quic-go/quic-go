package handshake

import (
	gocrypto "crypto"
	"crypto/aes"
	"crypto/cipher"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var quicVersion1Salt = []byte{0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38}

func newInitialAEAD(connID protocol.ConnectionID, pers protocol.Perspective) (Sealer, Opener, error) {
	clientSecret, serverSecret := computeSecrets(connID)
	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}
	myKey, _, myIV := computeInitialKeyAndIV(mySecret)
	otherKey, _, otherIV := computeInitialKeyAndIV(otherSecret)

	encrypterCipher, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, nil, err
	}
	encrypter, err := cipher.NewGCM(encrypterCipher)
	if err != nil {
		return nil, nil, err
	}
	decrypterCipher, err := aes.NewCipher(otherKey)
	if err != nil {
		return nil, nil, err
	}
	decrypter, err := cipher.NewGCM(decrypterCipher)
	if err != nil {
		return nil, nil, err
	}
	return newSealer(encrypter, myIV), newOpener(decrypter, otherIV), nil
}

func computeSecrets(connID protocol.ConnectionID) (clientSecret, serverSecret []byte) {
	initialSecret := crypto.HkdfExtract(gocrypto.SHA256, connID, quicVersion1Salt)
	clientSecret = crypto.HkdfExpandLabel(gocrypto.SHA256, initialSecret, "client in", gocrypto.SHA256.Size())
	serverSecret = crypto.HkdfExpandLabel(gocrypto.SHA256, initialSecret, "server in", gocrypto.SHA256.Size())
	return
}

func computeInitialKeyAndIV(secret []byte) (key, pnKey, iv []byte) {
	key = crypto.HkdfExpandLabel(gocrypto.SHA256, secret, "key", 16)
	pnKey = crypto.HkdfExpandLabel(gocrypto.SHA256, secret, "pn", 16)
	iv = crypto.HkdfExpandLabel(gocrypto.SHA256, secret, "iv", 12)
	return
}
