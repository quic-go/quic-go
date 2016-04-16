package crypto

// A Signer holds a certificate and a private key
type Signer interface {
	SignServerProof(chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertCompressed() []byte
	GetCertUncompressed() []byte
}
