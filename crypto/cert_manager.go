package crypto

import (
	"errors"

	"github.com/lucas-clemente/quic-go/qerr"
)

// CertManager manages the certificates sent by the server
type CertManager struct {
	chain [][]byte
}

var errNoCertificateChain = errors.New("No certicifate chain loaded")

// SetData takes the byte-slice sent in the SHLO and decompresses it into the certificate chain
func (c *CertManager) SetData(data []byte) error {
	chain, err := decompressChain(data)
	if err != nil {
		return qerr.ProofInvalid
	}
	c.chain = chain

	return nil
}

// GetLeafCert returns the leaf certificate of the certificate chain
// it errors if the certificate chain has not yet been set
func (c *CertManager) GetLeafCert() []byte {
	if len(c.chain) == 0 {
		return nil
	}
	return c.chain[0]
}
