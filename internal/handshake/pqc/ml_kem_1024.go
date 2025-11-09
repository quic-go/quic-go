package pqc

import (
	"crypto/mlkem"
	"fmt"
)

// MLKEM1024Provider implements CryptoProvider for ML-KEM-1024
type MLKEM1024Provider struct{}

var _ CryptoProvider = &MLKEM1024Provider{}

func NewMLKEM1024Provider() *MLKEM1024Provider {
	return &MLKEM1024Provider{}
}

func (p *MLKEM1024Provider) GenerateKeyPair() (KeyExchange, error) {
	decapKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
	}

	return &MLKEM1024KeyExchange{
		encapKey: decapKey.EncapsulationKey(),
		decapKey: decapKey,
	}, nil
}

func (p *MLKEM1024Provider) Mode() CryptoMode {
	return ModePQC
}

func (p *MLKEM1024Provider) KeyExchangeAlgorithm() string {
	return "ML-KEM-1024"
}

func (p *MLKEM1024Provider) SignatureAlgorithm() string {
	return "ML-DSA-87"
}

func (p *MLKEM1024Provider) GenerateSigner() (Signer, error) {
	return NewMLDSA87Signer()
}

func (p *MLKEM1024Provider) SecurityLevel() int {
	return 1024
}

// MLKEM1024KeyExchange implements KeyExchange for ML-KEM-1024
type MLKEM1024KeyExchange struct {
	encapKey   *mlkem.EncapsulationKey1024
	decapKey   *mlkem.DecapsulationKey1024
	ciphertext []byte // Stored ciphertext for server-side
}

var _ KeyExchange = &MLKEM1024KeyExchange{}

func (k *MLKEM1024KeyExchange) PublicKey() []byte {
	// If ciphertext is set (server side after encapsulation), return it
	if len(k.ciphertext) > 0 {
		return k.ciphertext
	}
	// Otherwise return the encapsulation key (client side)
	return k.encapKey.Bytes()
}

func (k *MLKEM1024KeyExchange) DeriveSharedSecret(peerPublicKeyBytes []byte, isClient bool) ([]byte, error) {
	if isClient {
		// Client side: decapsulate using received ciphertext
		if k.decapKey == nil {
			return nil, fmt.Errorf("decapsulation key not available")
		}
		sharedSecret, err := k.decapKey.Decapsulate(peerPublicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decapsulate: %w", err)
		}
		return sharedSecret, nil
	} else {
		// Server side: encapsulate using client's public key
		peerEncapKey, err := mlkem.NewEncapsulationKey1024(peerPublicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client public key: %w", err)
		}

		sharedSecret, ciphertext := peerEncapKey.Encapsulate()

		// Store ciphertext so PublicKey() returns it
		k.ciphertext = ciphertext

		return sharedSecret, nil
	}
}
