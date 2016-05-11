package crypto

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"strings"

	"github.com/lucas-clemente/quic-go/utils"
)

// rsaSigner stores a key and a certificate for the server proof
type rsaSigner struct {
	config *tls.Config
}

// NewRSASigner loads the key and cert from files
func NewRSASigner(tlsConfig *tls.Config) (Signer, error) {
	return &rsaSigner{config: tlsConfig}, nil
}

// SignServerProof signs CHLO and server config for use in the server proof
func (kd *rsaSigner) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	cert, err := kd.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	key, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("only RSA keys are supported for now")
	}

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
	return rsa.SignPSS(
		rand.Reader,
		key,
		crypto.SHA256,
		hash.Sum(nil),
		&rsa.PSSOptions{SaltLength: 32},
	)
}

// GetCertsCompressed gets the certificate in the format described by the QUIC crypto doc
func (kd *rsaSigner) GetCertsCompressed(sni string) ([]byte, error) {
	cert, err := kd.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}

	b := &bytes.Buffer{}
	totalUncompressedLen := 0
	for _, c := range cert.Certificate {
		// Entry type compressed
		b.WriteByte(1)
		totalUncompressedLen += len(c)
	}
	// Entry type end_of_list
	b.WriteByte(0)
	// Data + individual lengths as uint32
	utils.WriteUint32(b, uint32(totalUncompressedLen+4*len(cert.Certificate)))
	gz, err := zlib.NewWriterLevelDict(b, flate.BestCompression, certDictZlib)
	if err != nil {
		panic(err)
	}
	for _, c := range cert.Certificate {
		lenCert := len(c)
		gz.Write([]byte{
			byte(lenCert & 0xff),
			byte((lenCert >> 8) & 0xff),
			byte((lenCert >> 16) & 0xff),
			byte((lenCert >> 24) & 0xff),
		})
		gz.Write(c)
	}
	gz.Close()
	return b.Bytes(), nil
}

// GetLeafCert gets the leaf certificate
func (kd *rsaSigner) GetLeafCert(sni string) ([]byte, error) {
	cert, err := kd.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return cert.Certificate[0], nil
}

func (kd *rsaSigner) getCertForSNI(sni string) (*tls.Certificate, error) {
	if kd.config.GetCertificate != nil {
		cert, err := kd.config.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	if len(kd.config.NameToCertificate) != 0 {
		if cert, ok := kd.config.NameToCertificate[sni]; ok {
			return cert, nil
		}
		wildcardSNI := "*" + strings.TrimLeftFunc(sni, func(r rune) bool { return r != '.' })
		if cert, ok := kd.config.NameToCertificate[wildcardSNI]; ok {
			return cert, nil
		}
	}
	if len(kd.config.Certificates) != 0 {
		return &kd.config.Certificates[0], nil
	}
	return nil, errors.New("no matching certificate found")
}
