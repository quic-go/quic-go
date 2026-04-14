package qtls

import (
	"testing"
	"time"
)

func TestGenerateHybridCertificate(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		t.Run(mldsaLevelName(level), func(t *testing.T) {
			certBytes, signer, err := GenerateHybridCertificate(
				level, "Test Org", []string{"localhost"}, 24*time.Hour,
			)
			if err != nil {
				t.Fatalf("GenerateHybridCertificate(%d) failed: %v", level, err)
			}
			if len(certBytes) == 0 {
				t.Fatal("certificate bytes are empty")
			}
			if signer == nil {
				t.Fatal("signer is nil")
			}

			// Verify the signer produces a HybridPublicKey
			pub := signer.Public()
			if _, ok := pub.(*HybridPublicKey); !ok {
				t.Fatalf("signer.Public() returned %T, want *HybridPublicKey", pub)
			}
		})
	}
}

func TestIsHybridCertificateBytes(t *testing.T) {
	certBytes, _, err := GenerateHybridCertificate(
		65, "Test Org", []string{"localhost"}, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !IsHybridCertificateBytes(certBytes) {
		t.Fatal("IsHybridCertificateBytes() returned false for a hybrid certificate")
	}

	// ML-DSA certificate should not be detected as hybrid
	mldsaCert, _, err := GenerateMLDSACertificate(65, "Test Org", []string{"localhost"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if IsHybridCertificateBytes(mldsaCert) {
		t.Fatal("IsHybridCertificateBytes() returned true for an ML-DSA certificate")
	}
}

func TestParseHybridCertificate(t *testing.T) {
	certBytes, _, err := GenerateHybridCertificate(
		65, "Test Org", []string{"localhost", "example.com"}, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	hybridPub, cert, err := ParseHybridCertificate(certBytes)
	if err != nil {
		t.Fatalf("ParseHybridCertificate() failed: %v", err)
	}

	if hybridPub == nil {
		t.Fatal("hybrid public key is nil")
	}
	if hybridPub.MLDSALevel() != 65 {
		t.Fatalf("ML-DSA level = %d, want 65", hybridPub.MLDSALevel())
	}
	if len(hybridPub.Ed25519PublicKeyBytes()) == 0 {
		t.Fatal("Ed25519 public key bytes are empty")
	}
	if len(hybridPub.MLDSAPublicKey().Bytes()) == 0 {
		t.Fatal("ML-DSA public key bytes are empty")
	}

	if cert == nil {
		t.Fatal("certificate is nil")
	}
	if cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("Organization = %q, want %q", cert.Subject.Organization[0], "Test Org")
	}
}

func TestVerifyHybridCertificateSignature(t *testing.T) {
	for _, level := range []int{44, 65, 87} {
		t.Run(mldsaLevelName(level), func(t *testing.T) {
			certBytes, _, err := GenerateHybridCertificate(
				level, "Test Org", []string{"localhost"}, 24*time.Hour,
			)
			if err != nil {
				t.Fatal(err)
			}

			if err := VerifyHybridCertificateSignature(certBytes); err != nil {
				t.Fatalf("VerifyHybridCertificateSignature() failed: %v", err)
			}
		})
	}
}

func TestVerifyHybridCertificateSignatureCorrupted(t *testing.T) {
	certBytes, _, err := GenerateHybridCertificate(
		65, "Test Org", []string{"localhost"}, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the certificate
	corrupted := make([]byte, len(certBytes))
	copy(corrupted, certBytes)
	// Flip a byte near the end (in the signature area)
	corrupted[len(corrupted)-20] ^= 0xFF

	// Verification should fail (either parsing or signature check)
	err = VerifyHybridCertificateSignature(corrupted)
	if err == nil {
		t.Fatal("VerifyHybridCertificateSignature() should have failed on corrupted certificate")
	}
}

func mldsaLevelName(level int) string {
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
