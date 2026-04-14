package pqc

import "fmt"

// HybridProvider implements CryptoProvider for hybrid Ed25519 + ML-DSA signatures
// with ML-KEM key exchange. This provides transitional security against both
// classical and quantum adversaries.
type HybridProvider struct {
	mlkemLevel int // 512, 768, or 1024
	mldsaLevel int // 44, 65, or 87
}

var _ CryptoProvider = &HybridProvider{}

// NewHybridProvider creates a hybrid provider for the given security level.
// The security level maps to ML-KEM key exchange and ML-DSA signature levels.
func NewHybridProvider(securityLevel PQCSecurityLevel) *HybridProvider {
	return &HybridProvider{
		mlkemLevel: securityLevel.KEMLevel(),
		mldsaLevel: securityLevel.DSALevel(),
	}
}

func (p *HybridProvider) GenerateKeyPair() (KeyExchange, error) {
	// Delegate to the appropriate ML-KEM provider for key exchange.
	// The hybrid key exchange (X25519 + ML-KEM) is handled at the TLS layer.
	kemProvider, err := NewProvider(ModePQC, PQCSecurityLevel(p.mlkemLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to create KEM provider: %w", err)
	}
	return kemProvider.GenerateKeyPair()
}

func (p *HybridProvider) GenerateSigner() (Signer, error) {
	return NewHybridSigner(p.mldsaLevel)
}

func (p *HybridProvider) Mode() CryptoMode {
	return ModeHybrid
}

func (p *HybridProvider) KeyExchangeAlgorithm() string {
	return fmt.Sprintf("X25519-ML-KEM-%d", p.mlkemLevel)
}

func (p *HybridProvider) SignatureAlgorithm() string {
	return fmt.Sprintf("Hybrid-Ed25519-ML-DSA-%d", p.mldsaLevel)
}

func (p *HybridProvider) SecurityLevel() int {
	return p.mlkemLevel
}
