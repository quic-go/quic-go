package pqc

// CryptoProvider defines the interface for cryptographic operations
type CryptoProvider interface {
	// GenerateKeyPair generates a new key exchange keypair
	GenerateKeyPair() (KeyExchange, error)

	// GenerateSigner generates a new signature keypair
	GenerateSigner() (Signer, error)

	// Mode returns the crypto mode this provider implements
	Mode() CryptoMode

	// KeyExchangeAlgorithm returns the name of the key exchange algorithm
	KeyExchangeAlgorithm() string

	// SignatureAlgorithm returns the name of the signature algorithm
	SignatureAlgorithm() string

	// SecurityLevel returns the security level
	SecurityLevel() int
}

// KeyExchange defines the interface for key exchange operations
type KeyExchange interface {
	// PublicKey returns the public key bytes
	PublicKey() []byte

	// DeriveSharedSecret derives a shared secret from the peer's public key
	// isClient indicates whether this is the client side of the handshake
	DeriveSharedSecret(peerPublicKey []byte, isClient bool) ([]byte, error)
}
