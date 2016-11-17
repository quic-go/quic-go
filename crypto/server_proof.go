package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// signServerProof signs CHLO and server config for use in the server proof
func signServerProof(cert *tls.Certificate, chlo []byte, serverConfigData []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte("QUIC CHLO and server config signature\x00"))
	chloHash := sha256.Sum256(chlo)
	hash.Write([]byte{32, 0, 0, 0})
	hash.Write(chloHash[:])
	hash.Write(serverConfigData)

	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("expected PrivateKey to implement crypto.Signer")
	}

	opts := crypto.SignerOpts(crypto.SHA256)

	if _, ok = key.(*rsa.PrivateKey); ok {
		opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	}

	return key.Sign(rand.Reader, hash.Sum(nil), opts)
}
