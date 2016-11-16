package crypto

import (
	"errors"

	"github.com/lucas-clemente/quic-go/qerr"
)

// CertManager manages the certificates sent by the server
type CertManager interface {
	SetData([]byte) error
	GetLeafCert() []byte
}

type certManager struct {
	chain [][]byte
}

var _ CertManager = &certManager{}

var errNoCertificateChain = errors.New("No certicifate chain loaded")

// NewCertManager creates a new CertManager
func NewCertManager() CertManager {
	return &certManager{}
}

// SetData takes the byte-slice sent in the SHLO and decompresses it into the certificate chain
func (c *certManager) SetData(data []byte) error {
	chain, err := decompressChain(data)
	if err != nil {
		return qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")
	}
	c.chain = chain

	return nil
}

// GetLeafCert returns the leaf certificate of the certificate chain
// it errors if the certificate chain has not yet been set
func (c *certManager) GetLeafCert() []byte {
	if len(c.chain) == 0 {
		return nil
	}
	return c.chain[0]
}
