package pqc

import (
	"crypto/mlkem"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
)

// ML-KEM-512 Provider (128-bit security level)

// MLKEM512Provider implements CryptoProvider for ML-KEM-512
type MLKEM512Provider struct{}

var _ CryptoProvider = &MLKEM512Provider{}

func NewMLKEM512Provider() *MLKEM512Provider {
	return &MLKEM512Provider{}
}

func (p *MLKEM512Provider) GenerateKeyPair() (KeyExchange, error) {
	pubKey, privKey, err := mlkem512.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-KEM-512 keypair: %w", err)
	}

	return &MLKEM512KeyExchange{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

func (p *MLKEM512Provider) Mode() CryptoMode {
	return ModePQC
}

func (p *MLKEM512Provider) KeyExchangeAlgorithm() string {
	return "ML-KEM-512"
}

func (p *MLKEM512Provider) SignatureAlgorithm() string {
	return "ML-DSA-44"
}

func (p *MLKEM512Provider) GenerateSigner() (Signer, error) {
	return NewMLDSA44Signer()
}

func (p *MLKEM512Provider) SecurityLevel() int {
	return 512
}

// MLKEM512KeyExchange implements KeyExchange for ML-KEM-512
type MLKEM512KeyExchange struct {
	publicKey  *mlkem512.PublicKey
	privateKey *mlkem512.PrivateKey
	ciphertext []byte // Stored ciphertext for server-side
}

var _ KeyExchange = &MLKEM512KeyExchange{}

func (k *MLKEM512KeyExchange) PublicKey() []byte {
	// If ciphertext is set (server side after encapsulation), return it
	if len(k.ciphertext) > 0 {
		return k.ciphertext
	}
	// Otherwise return the encapsulation key (client side)
	pubBytes, _ := k.publicKey.MarshalBinary()
	return pubBytes
}

func (k *MLKEM512KeyExchange) DeriveSharedSecret(peerPublicKeyBytes []byte, isClient bool) ([]byte, error) {
	if isClient {
		// Client side: decapsulate using received ciphertext
		if k.privateKey == nil {
			return nil, fmt.Errorf("private key not available")
		}

		// CIRCL mlkem512 requires exact ciphertext size (768 bytes)
		if len(peerPublicKeyBytes) != 768 {
			return nil, fmt.Errorf("invalid ciphertext size: got %d, want 768", len(peerPublicKeyBytes))
		}

		sharedSecret := make([]byte, 32) // ML-KEM-512 shared secret is 32 bytes
		k.privateKey.DecapsulateTo(sharedSecret, peerPublicKeyBytes)
		return sharedSecret, nil
	} else {
		// Server side: encapsulate using client's public key
		var peerPubKey mlkem512.PublicKey
		if err := peerPubKey.Unpack(peerPublicKeyBytes); err != nil {
			return nil, fmt.Errorf("failed to parse client public key: %w", err)
		}

		ciphertext := make([]byte, 768)      // ML-KEM-512 ciphertext size
		sharedSecret := make([]byte, 32)     // ML-KEM-512 shared secret size
		peerPubKey.EncapsulateTo(ciphertext, sharedSecret, nil)

		// Store ciphertext so PublicKey() returns it
		k.ciphertext = ciphertext

		return sharedSecret, nil
	}
}

// ML-KEM-768 Provider (192-bit security level) - RECOMMENDED

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

// ML-KEM-1024 Provider (256-bit security level)

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

// NewMLKEMProvider creates an ML-KEM provider based on security level
func NewMLKEMProvider(level int) (CryptoProvider, error) {
	switch level {
	case 512:
		return NewMLKEM512Provider(), nil
	case 768:
		return NewMLKEM768Provider(), nil
	case 1024:
		return NewMLKEM1024Provider(), nil
	default:
		return nil, fmt.Errorf("unsupported ML-KEM security level: %d (must be 512, 768, or 1024)", level)
	}
}
