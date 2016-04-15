package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/utils"
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
	if len(chlo) > 0 {
		// Version >= 31
		hash.Write([]byte("QUIC CHLO and server config signature\x00"))
		chloHash := sha256.Sum256(chlo)
		hash.Write([]byte{32, 0, 0, 0})
		hash.Write(chloHash[:])
	} else {
		hash.Write([]byte("QUIC server config signature\x00"))
	}
	hash.Write(serverConfigData)
	return rsa.SignPSS(rand.Reader, kd.key, crypto.SHA256, hash.Sum(nil), &rsa.PSSOptions{SaltLength: 32})
}

// GetCertCompressed gets the certificate in the format described by the QUIC crypto doc
func (kd *KeyData) GetCertCompressed() []byte {
	b := &bytes.Buffer{}
	b.WriteByte(1) // Entry type compressed
	b.WriteByte(0) // Entry type end_of_list
	utils.WriteUint32(b, uint32(len(kd.cert.Raw)+4))
	gz, err := zlib.NewWriterLevelDict(b, flate.BestCompression, certDictZlib)
	if err != nil {
		panic(err)
	}
	lenCert := len(kd.cert.Raw)
	gz.Write([]byte{
		byte(lenCert & 0xff),
		byte((lenCert >> 8) & 0xff),
		byte((lenCert >> 16) & 0xff),
		byte((lenCert >> 24) & 0xff),
	})
	gz.Write(kd.cert.Raw)
	gz.Close()
	return b.Bytes()
}

// GetCertUncompressed gets the certificate in DER
func (kd *KeyData) GetCertUncompressed() []byte {
	return kd.cert.Raw
}
