package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/handshake/pqc"
)

// TestPQCKeyExchangeVerification verifies that PQC key exchange produces expected key sizes
func TestPQCKeyExchangeVerification(t *testing.T) {
	testCases := []struct {
		name                   string
		provider               pqc.CryptoProvider
		expectedPublicKeySize  int
		expectedCiphertextSize int
		expectedSharedSecSize  int
	}{
		{
			name:                   "ML-KEM-512",
			provider:               pqc.NewMLKEM512Provider(),
			expectedPublicKeySize:  800, // ML-KEM-512 encapsulation key
			expectedCiphertextSize: 768, // ML-KEM-512 ciphertext
			expectedSharedSecSize:  32,  // Shared secret size
		},
		{
			name:                   "ML-KEM-768",
			provider:               pqc.NewMLKEM768Provider(),
			expectedPublicKeySize:  1184, // ML-KEM-768 encapsulation key
			expectedCiphertextSize: 1088, // ML-KEM-768 ciphertext
			expectedSharedSecSize:  32,   // Shared secret size
		},
		{
			name:                   "ML-KEM-1024",
			provider:               pqc.NewMLKEM1024Provider(),
			expectedPublicKeySize:  1568, // ML-KEM-1024 encapsulation key
			expectedCiphertextSize: 1568, // ML-KEM-1024 ciphertext
			expectedSharedSecSize:  32,   // Shared secret size
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing %s", tc.name)
			t.Logf("  Algorithm: %s", tc.provider.KeyExchangeAlgorithm())
			t.Logf("  Security Level: %d-bit", tc.provider.SecurityLevel())

			// Client generates keypair
			clientKex, err := tc.provider.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate client keypair: %v", err)
			}

			clientPubKey := clientKex.PublicKey()
			t.Logf("  Client public key size: %d bytes", len(clientPubKey))

			if len(clientPubKey) != tc.expectedPublicKeySize {
				t.Errorf("Client public key size mismatch: got %d, want %d",
					len(clientPubKey), tc.expectedPublicKeySize)
			}

			// Server encapsulates (generates shared secret + ciphertext)
			serverKex, err := tc.provider.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate server keypair: %v", err)
			}

			serverSharedSecret, err := serverKex.DeriveSharedSecret(clientPubKey, false)
			if err != nil {
				t.Fatalf("Server failed to derive shared secret: %v", err)
			}

			ciphertext := serverKex.PublicKey()
			t.Logf("  Server ciphertext size: %d bytes", len(ciphertext))
			t.Logf("  Server shared secret size: %d bytes", len(serverSharedSecret))

			if len(ciphertext) != tc.expectedCiphertextSize {
				t.Errorf("Ciphertext size mismatch: got %d, want %d",
					len(ciphertext), tc.expectedCiphertextSize)
			}

			if len(serverSharedSecret) != tc.expectedSharedSecSize {
				t.Errorf("Shared secret size mismatch: got %d, want %d",
					len(serverSharedSecret), tc.expectedSharedSecSize)
			}

			// Client decapsulates (derives same shared secret)
			clientSharedSecret, err := clientKex.DeriveSharedSecret(ciphertext, true)
			if err != nil {
				t.Fatalf("Client failed to derive shared secret: %v", err)
			}

			t.Logf("  Client shared secret size: %d bytes", len(clientSharedSecret))

			if len(clientSharedSecret) != tc.expectedSharedSecSize {
				t.Errorf("Client shared secret size mismatch: got %d, want %d",
					len(clientSharedSecret), tc.expectedSharedSecSize)
			}

			// Verify shared secrets match
			if string(clientSharedSecret) != string(serverSharedSecret) {
				t.Errorf("Shared secrets don't match!")
				t.Logf("  Client: %x...", clientSharedSecret[:8])
				t.Logf("  Server: %x...", serverSharedSecret[:8])
			} else {
				t.Logf("  ✅ Shared secrets match: %x...", clientSharedSecret[:8])
			}

			t.Logf("  ✅ %s verification complete!", tc.name)
		})
	}
}
