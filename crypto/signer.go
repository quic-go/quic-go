package crypto

// A Signer holds a certificate and a private key
type Signer interface {
	SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertCompressed(sni string) []byte
	GetCertUncompressed(sni string) []byte
}
