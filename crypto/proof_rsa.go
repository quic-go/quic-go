package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io/ioutil"
)

// KeyData stores a key and a certificate for the server proof
type KeyData struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// LoadKeyData loads the key and cert from files
func LoadKeyData(certFileName string, keyFileName string) (*KeyData, error) {
	keyDER, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	certDER, err := ioutil.ReadFile(certFileName)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &KeyData{key: key, cert: cert}, nil
}

// SignServerProof signs CHLO and server config for use in the server proof
func (kd *KeyData) SignServerProof(chlo []byte, serverConfigData []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte("QUIC server config signature\x00"))
	chloHash := sha256.Sum256(chlo)
	hash.Write(chloHash[:])
	hash.Write(serverConfigData)
	return rsa.SignPSS(rand.Reader, kd.key, crypto.SHA256, hash.Sum(nil), nil)
}
