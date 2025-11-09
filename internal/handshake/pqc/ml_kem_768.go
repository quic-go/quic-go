package pqc

import (
	"crypto/mlkem"
	"fmt"
)

// MLKEM768Provider implements CryptoProvider for ML-KEM-768
type MLKEM768Provider struct{}

var _ CryptoProvider = &MLKEM768Provider{}

func NewMLKEM768Provider() *MLKEM768Provider {
	return &MLKEM768Provider{}
}

func (p *MLKEM768Provider) GenerateKeyPair() (KeyExchange, error) {
	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-768 keypair: %w", err)
	}

	return &MLKEM768KeyExchange{
		encapKey: decapKey.EncapsulationKey(),
		decapKey: decapKey,
	}, nil
}

func (p *MLKEM768Provider) Mode() CryptoMode {
	return ModePQC
}

func (p *MLKEM768Provider) KeyExchangeAlgorithm() string {
	return "ML-KEM-768"
}

func (p *MLKEM768Provider) SignatureAlgorithm() string {
	return "ML-DSA-65"
}

func (p *MLKEM768Provider) GenerateSigner() (Signer, error) {
	return NewMLDSA65Signer()
}

func (p *MLKEM768Provider) SecurityLevel() int {
	return 768
}

// MLKEM768KeyExchange implements KeyExchange for ML-KEM-768
type MLKEM768KeyExchange struct {
	encapKey   *mlkem.EncapsulationKey768
	decapKey   *mlkem.DecapsulationKey768
	ciphertext []byte // Stored ciphertext for server-side
}

var _ KeyExchange = &MLKEM768KeyExchange{}

func (k *MLKEM768KeyExchange) PublicKey() []byte {
	// If ciphertext is set (server side after encapsulation), return it
	if len(k.ciphertext) > 0 {
		return k.ciphertext
	}
	// Otherwise return the encapsulation key (client side)
	return k.encapKey.Bytes()
}

func (k *MLKEM768KeyExchange) DeriveSharedSecret(peerPublicKeyBytes []byte, isClient bool) ([]byte, error) {
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
		peerEncapKey, err := mlkem.NewEncapsulationKey768(peerPublicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client public key: %w", err)
		}

		sharedSecret, ciphertext := peerEncapKey.Encapsulate()

		// Store ciphertext so PublicKey() returns it
		k.ciphertext = ciphertext

		return sharedSecret, nil
	}
}
