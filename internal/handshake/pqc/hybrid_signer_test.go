package pqc

import (
	"testing"
)

func TestHybridSignerNewAndSign(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		t.Run(algName(level), func(t *testing.T) {
			signer, err := NewHybridSigner(level)
			if err != nil {
				t.Fatalf("NewHybridSigner(%d) failed: %v", level, err)
			}

			if signer.Algorithm() == "" {
				t.Fatal("Algorithm() returned empty string")
			}
			if signer.SecurityLevel() != level {
				t.Fatalf("SecurityLevel() = %d, want %d", signer.SecurityLevel(), level)
			}
			if len(signer.PublicKey()) == 0 {
				t.Fatal("PublicKey() returned empty bytes")
			}
			if len(signer.ECDSAPublicKey()) == 0 {
				t.Fatal("ECDSAPublicKey() returned empty bytes")
			}
			if len(signer.MLDSAPublicKey()) == 0 {
				t.Fatal("MLDSAPublicKey() returned empty bytes")
			}

			message := []byte("test message for hybrid signing")
			sig, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("Sign() returned empty signature")
			}

			if !signer.Verify(message, sig) {
				t.Fatal("Verify() returned false for valid signature")
			}
		})
	}
}

func TestHybridSignerVerifyFailsOnCorruptedECDSA(t *testing.T) {
	signer, err := NewHybridSigner(65)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the signature by modifying a byte
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	// Flip a byte near the start (inside the ECDSA portion of the ASN.1 structure)
	if len(corrupted) > 10 {
		corrupted[10] ^= 0xFF
	}

	if signer.Verify(message, corrupted) {
		t.Fatal("Verify() should return false for corrupted signature")
	}
}

func TestHybridSignerVerifyFailsOnWrongMessage(t *testing.T) {
	signer, err := NewHybridSigner(65)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	if signer.Verify([]byte("wrong message"), sig) {
		t.Fatal("Verify() should return false for wrong message")
	}
}

func TestHybridSignerInvalidLevel(t *testing.T) {
	_, err := NewHybridSigner(99)
	if err == nil {
		t.Fatal("NewHybridSigner(99) should have failed")
	}
}

func TestParseCompositePublicKey(t *testing.T) {
	signer, err := NewHybridSigner(65)
	if err != nil {
		t.Fatal(err)
	}

	compositeKey := signer.PublicKey()
	ecdsaPub, mldsaPub, err := ParseCompositePublicKey(compositeKey)
	if err != nil {
		t.Fatalf("ParseCompositePublicKey() failed: %v", err)
	}
	if len(ecdsaPub) == 0 {
		t.Fatal("ECDSA public key is empty")
	}
	if len(mldsaPub) == 0 {
		t.Fatal("ML-DSA public key is empty")
	}
}

func TestParseCompositeSignature(t *testing.T) {
	signer, err := NewHybridSigner(65)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaSig, mldsaSig, err := ParseCompositeSignature(sig)
	if err != nil {
		t.Fatalf("ParseCompositeSignature() failed: %v", err)
	}
	if len(ecdsaSig) == 0 {
		t.Fatal("ECDSA signature is empty")
	}
	if len(mldsaSig) == 0 {
		t.Fatal("ML-DSA signature is empty")
	}
}

func TestVerifyHybridSignatureStandalone(t *testing.T) {
	signer, err := NewHybridSigner(65)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("standalone verification test")
	sig, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyHybridSignature(
		signer.ECDSAPublicKey(),
		signer.MLDSAPublicKey(),
		message, sig, 65,
	)
	if err != nil {
		t.Fatalf("VerifyHybridSignature() error: %v", err)
	}
	if !ok {
		t.Fatal("VerifyHybridSignature() returned false for valid signature")
	}
}

func TestHybridProviderInterface(t *testing.T) {
	provider := NewHybridProvider(SecurityLevel192)

	if provider.Mode() != ModeHybrid {
		t.Fatalf("Mode() = %s, want %s", provider.Mode(), ModeHybrid)
	}
	if provider.SecurityLevel() != 768 {
		t.Fatalf("SecurityLevel() = %d, want 768", provider.SecurityLevel())
	}
	if provider.SignatureAlgorithm() == "" {
		t.Fatal("SignatureAlgorithm() returned empty string")
	}
	if provider.KeyExchangeAlgorithm() == "" {
		t.Fatal("KeyExchangeAlgorithm() returned empty string")
	}

	signer, err := provider.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner() failed: %v", err)
	}
	_, ok := signer.(*HybridSigner)
	if !ok {
		t.Fatalf("GenerateSigner() returned %T, want *HybridSigner", signer)
	}
}

func TestHybridProviderViaFactory(t *testing.T) {
	provider, err := NewProvider(ModeHybrid, SecurityLevel192)
	if err != nil {
		t.Fatalf("NewProvider(ModeHybrid, 768) failed: %v", err)
	}
	if provider.Mode() != ModeHybrid {
		t.Fatalf("Mode() = %s, want hybrid", provider.Mode())
	}
}

func algName(level int) string {
	switch level {
	case 44:
		return "ML-DSA-44"
	case 65:
		return "ML-DSA-65"
	case 87:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}
