package crypto

import (
	"crypto/x509"
	"errors"
	"hash/fnv"

	"github.com/lucas-clemente/quic-go/qerr"
)

// CertManager manages the certificates sent by the server
type CertManager interface {
	SetData([]byte) error
	GetLeafCert() []byte
	GetLeafCertHash() (uint64, error)
	VerifyServerProof(proof, chlo, serverConfigData []byte) bool
	Verify(hostname string) error
}

type certManager struct {
	chain []*x509.Certificate
}

var _ CertManager = &certManager{}

var errNoCertificateChain = errors.New("CertManager BUG: No certicifate chain loaded")

// NewCertManager creates a new CertManager
func NewCertManager() CertManager {
	return &certManager{}
}

// SetData takes the byte-slice sent in the SHLO and decompresses it into the certificate chain
func (c *certManager) SetData(data []byte) error {
	byteChain, err := decompressChain(data)
	if err != nil {
		return qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")
	}

	chain := make([]*x509.Certificate, len(byteChain), len(byteChain))
	for i, data := range byteChain {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return err
		}
		chain[i] = cert
	}

	c.chain = chain
	return nil
}

// GetLeafCert returns the leaf certificate of the certificate chain
// it returns nil if the certificate chain has not yet been set
func (c *certManager) GetLeafCert() []byte {
	if len(c.chain) == 0 {
		return nil
	}
	return c.chain[0].Raw
}

// GetLeafCertHash calculates the FNV1a_64 hash of the leaf certificate
func (c *certManager) GetLeafCertHash() (uint64, error) {
	leafCert := c.GetLeafCert()
	if leafCert == nil {
		return 0, errNoCertificateChain
	}

	h := fnv.New64a()
	_, err := h.Write(leafCert)
	if err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}

// VerifyServerProof verifies the signature of the server config
// it should only be called after the certificate chain has been set, otherwise it returns false
func (c *certManager) VerifyServerProof(proof, chlo, serverConfigData []byte) bool {
	if len(c.chain) == 0 {
		return false
	}

	return verifyServerProof(proof, c.chain[0], chlo, serverConfigData)
}

// Verify verifies the certificate chain
func (c *certManager) Verify(hostname string) error {
	if len(c.chain) == 0 {
		return errNoCertificateChain
	}

	leafCert := c.chain[0]
	opts := x509.VerifyOptions{DNSName: hostname}

	// the first certificate is the leaf certificate, all others are intermediates
	if len(c.chain) > 1 {
		intermediates := x509.NewCertPool()
		for i := 1; i < len(c.chain); i++ {
			intermediates.AddCert(c.chain[i])
		}
		opts.Intermediates = intermediates
	}

	_, err := leafCert.Verify(opts)
	return err
}
