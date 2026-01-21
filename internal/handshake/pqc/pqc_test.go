package pqc

import (
	"fmt"
	"testing"
)

func TestCryptoModeValidation(t *testing.T) {
	tests := []struct {
		mode  CryptoMode
		valid bool
	}{
		{ModeClassical, true},
		{ModePQC, true},
		{ModeAuto, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("CryptoMode(%q).IsValid() = %v, want %v", tt.mode, got, tt.valid)
			}
		})
	}
}

func TestSecurityLevelValidation(t *testing.T) {
	tests := []struct {
		level PQCSecurityLevel
		valid bool
	}{
		{SecurityLevel128, true},
		{SecurityLevel192, true},
		{SecurityLevel256, true},
		{PQCSecurityLevel(256), false},
		{PQCSecurityLevel(0), false},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.level)), func(t *testing.T) {
			if got := tt.level.IsValid(); got != tt.valid {
				t.Errorf("PQCSecurityLevel(%d).IsValid() = %v, want %v", tt.level, got, tt.valid)
			}
		})
	}
}

func TestSecurityLevelMappings(t *testing.T) {
	tests := []struct {
		level    PQCSecurityLevel
		kemLevel int
		dsaLevel int
	}{
		{SecurityLevel128, 512, 44},
		{SecurityLevel192, 768, 65},
		{SecurityLevel256, 1024, 87},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.level)), func(t *testing.T) {
			if got := tt.level.KEMLevel(); got != tt.kemLevel {
				t.Errorf("KEMLevel() = %d, want %d", got, tt.kemLevel)
			}
			if got := tt.level.DSALevel(); got != tt.dsaLevel {
				t.Errorf("DSALevel() = %d, want %d", got, tt.dsaLevel)
			}
		})
	}
}

func TestClassicalProvider(t *testing.T) {
	provider := NewClassicalProvider()

	if provider.Mode() != ModeClassical {
		t.Errorf("Mode() = %v, want %v", provider.Mode(), ModeClassical)
	}

	if provider.KeyExchangeAlgorithm() != "X25519" {
		t.Errorf("KeyExchangeAlgorithm() = %v, want X25519", provider.KeyExchangeAlgorithm())
	}

	if provider.SecurityLevel() != 128 {
		t.Errorf("SecurityLevel() = %d, want 128", provider.SecurityLevel())
	}
}

func TestClassicalKeyExchange(t *testing.T) {
	provider := NewClassicalProvider()

	// Generate client keypair
	clientKex, err := provider.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client keypair: %v", err)
	}

	// Generate server keypair
	serverKex, err := provider.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server keypair: %v", err)
	}

	// Test public key retrieval
	clientPubKey := clientKex.PublicKey()
	serverPubKey := serverKex.PublicKey()

	if len(clientPubKey) != 32 {
		t.Errorf("Client public key length = %d, want 32", len(clientPubKey))
	}

	if len(serverPubKey) != 32 {
		t.Errorf("Server public key length = %d, want 32", len(serverPubKey))
	}

	// Derive shared secrets
	clientSecret, err := clientKex.DeriveSharedSecret(serverPubKey, true)
	if err != nil {
		t.Fatalf("Client failed to derive shared secret: %v", err)
	}

	serverSecret, err := serverKex.DeriveSharedSecret(clientPubKey, false)
	if err != nil {
		t.Fatalf("Server failed to derive shared secret: %v", err)
	}

	// Verify shared secrets match
	if len(clientSecret) != 32 {
		t.Errorf("Client shared secret length = %d, want 32", len(clientSecret))
	}

	if len(serverSecret) != 32 {
		t.Errorf("Server shared secret length = %d, want 32", len(serverSecret))
	}

	// The secrets should match
	if string(clientSecret) != string(serverSecret) {
		t.Error("Shared secrets do not match")
	}
}

func TestMLKEM512Provider(t *testing.T) {
	provider := NewMLKEM512Provider()

	if provider.Mode() != ModePQC {
		t.Errorf("Mode() = %v, want %v", provider.Mode(), ModePQC)
	}

	if provider.KeyExchangeAlgorithm() != "ML-KEM-512" {
		t.Errorf("KeyExchangeAlgorithm() = %v, want ML-KEM-512", provider.KeyExchangeAlgorithm())
	}

	if provider.SecurityLevel() != 512 {
		t.Errorf("SecurityLevel() = %d, want 512", provider.SecurityLevel())
	}
}

func TestMLKEM768Provider(t *testing.T) {
	provider := NewMLKEM768Provider()

	if provider.Mode() != ModePQC {
		t.Errorf("Mode() = %v, want %v", provider.Mode(), ModePQC)
	}

	if provider.KeyExchangeAlgorithm() != "ML-KEM-768" {
		t.Errorf("KeyExchangeAlgorithm() = %v, want ML-KEM-768", provider.KeyExchangeAlgorithm())
	}

	if provider.SecurityLevel() != 768 {
		t.Errorf("SecurityLevel() = %d, want 768", provider.SecurityLevel())
	}
}

func TestMLKEM512KeyExchange(t *testing.T) {
	provider := NewMLKEM512Provider()

	// Generate keypair
	kex, err := provider.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test public key retrieval
	pubKey := kex.PublicKey()

	// ML-KEM-512 public key should be 800 bytes
	if len(pubKey) != 800 {
		t.Errorf("Public key length = %d, want 800", len(pubKey))
	}
}

func TestMLKEM768KeyExchange(t *testing.T) {
	provider := NewMLKEM768Provider()

	// Generate keypair
	kex, err := provider.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test public key retrieval
	pubKey := kex.PublicKey()

	// ML-KEM-768 public key should be 1184 bytes
	if len(pubKey) != 1184 {
		t.Errorf("Public key length = %d, want 1184", len(pubKey))
	}
}

func TestMLKEM1024Provider(t *testing.T) {
	provider := NewMLKEM1024Provider()

	if provider.Mode() != ModePQC {
		t.Errorf("Mode() = %v, want %v", provider.Mode(), ModePQC)
	}

	if provider.KeyExchangeAlgorithm() != "ML-KEM-1024" {
		t.Errorf("KeyExchangeAlgorithm() = %v, want ML-KEM-1024", provider.KeyExchangeAlgorithm())
	}

	if provider.SecurityLevel() != 1024 {
		t.Errorf("SecurityLevel() = %d, want 1024", provider.SecurityLevel())
	}
}

func TestMLKEM1024KeyExchange(t *testing.T) {
	provider := NewMLKEM1024Provider()

	// Generate keypair
	kex, err := provider.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Test public key retrieval
	pubKey := kex.PublicKey()

	// ML-KEM-1024 public key should be 1568 bytes
	if len(pubKey) != 1568 {
		t.Errorf("Public key length = %d, want 1568", len(pubKey))
	}
}

func TestProviderFactory(t *testing.T) {
	tests := []struct {
		mode          CryptoMode
		securityLevel PQCSecurityLevel
		wantAlgo      string
		wantErr       bool
	}{
		{ModeClassical, SecurityLevel192, "X25519", false},
		{ModePQC, SecurityLevel128, "ML-KEM-512", false},
		{ModePQC, SecurityLevel192, "ML-KEM-768", false},
		{ModePQC, SecurityLevel256, "ML-KEM-1024", false},
		{ModeAuto, SecurityLevel192, "ML-KEM-768", false},
		{"invalid", SecurityLevel192, "", true},
		{ModePQC, PQCSecurityLevel(999), "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode)+"_"+string(rune(tt.securityLevel)), func(t *testing.T) {
			provider, err := NewProvider(tt.mode, tt.securityLevel)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if provider.KeyExchangeAlgorithm() != tt.wantAlgo {
				t.Errorf("KeyExchangeAlgorithm() = %v, want %v", provider.KeyExchangeAlgorithm(), tt.wantAlgo)
			}
		})
	}
}

func TestGetProviderForSecurityLevel(t *testing.T) {
	tests := []struct {
		level    int
		wantAlgo string
		wantErr  bool
	}{
		{128, "X25519", false},
		{512, "ML-KEM-512", false},
		{768, "ML-KEM-768", false},
		{1024, "ML-KEM-1024", false},
		{999, "", true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.level)), func(t *testing.T) {
			provider, err := GetProviderForSecurityLevel(tt.level)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if provider.KeyExchangeAlgorithm() != tt.wantAlgo {
				t.Errorf("KeyExchangeAlgorithm() = %v, want %v", provider.KeyExchangeAlgorithm(), tt.wantAlgo)
			}
		})
	}
}

// Benchmark tests
func BenchmarkClassicalKeyExchange(b *testing.B) {
	provider := NewClassicalProvider()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kex, err := provider.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_ = kex.PublicKey()
	}
}

func BenchmarkMLKEM512KeyExchange(b *testing.B) {
	provider := NewMLKEM512Provider()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kex, err := provider.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_ = kex.PublicKey()
	}
}

func BenchmarkMLKEM768KeyExchange(b *testing.B) {
	provider := NewMLKEM768Provider()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kex, err := provider.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_ = kex.PublicKey()
	}
}

func BenchmarkMLKEM1024KeyExchange(b *testing.B) {
	provider := NewMLKEM1024Provider()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kex, err := provider.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		_ = kex.PublicKey()
	}
}

// ML-DSA Signature Tests

func TestMLDSA44Signer(t *testing.T) {
	signer, err := NewMLDSA44Signer()
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-44 signer: %v", err)
	}

	if signer.Algorithm() != "ML-DSA-44" {
		t.Errorf("Expected algorithm ML-DSA-44, got %s", signer.Algorithm())
	}

	if signer.SecurityLevel() != 44 {
		t.Errorf("Expected security level 44, got %d", signer.SecurityLevel())
	}

	publicKey := signer.PublicKey()
	if len(publicKey) == 0 {
		t.Error("Public key is empty")
	}
}

func TestMLDSA65Signer(t *testing.T) {
	signer, err := NewMLDSA65Signer()
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-65 signer: %v", err)
	}

	if signer.Algorithm() != "ML-DSA-65" {
		t.Errorf("Expected algorithm ML-DSA-65, got %s", signer.Algorithm())
	}

	if signer.SecurityLevel() != 65 {
		t.Errorf("Expected security level 65, got %d", signer.SecurityLevel())
	}

	publicKey := signer.PublicKey()
	if len(publicKey) == 0 {
		t.Error("Public key is empty")
	}
}

func TestMLDSA87Signer(t *testing.T) {
	signer, err := NewMLDSA87Signer()
	if err != nil {
		t.Fatalf("Failed to create ML-DSA-87 signer: %v", err)
	}

	if signer.Algorithm() != "ML-DSA-87" {
		t.Errorf("Expected algorithm ML-DSA-87, got %s", signer.Algorithm())
	}

	if signer.SecurityLevel() != 87 {
		t.Errorf("Expected security level 87, got %d", signer.SecurityLevel())
	}

	publicKey := signer.PublicKey()
	if len(publicKey) == 0 {
		t.Error("Public key is empty")
	}
}

func TestMLDSA44SignAndVerify(t *testing.T) {
	signer, err := NewMLDSA44Signer()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Hello, PQC World!")

	// Sign the message
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify the signature
	if !signer.Verify(message, signature) {
		t.Error("Signature verification failed")
	}

	// Verify with wrong message should fail
	wrongMessage := []byte("Wrong message")
	if signer.Verify(wrongMessage, signature) {
		t.Error("Signature verification should have failed with wrong message")
	}

	// Verify with corrupted signature should fail
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF
	if signer.Verify(message, corruptedSignature) {
		t.Error("Signature verification should have failed with corrupted signature")
	}
}

func TestMLDSA65SignAndVerify(t *testing.T) {
	signer, err := NewMLDSA65Signer()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Test message for ML-DSA-65")

	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !signer.Verify(message, signature) {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	if signer.Verify([]byte("Different message"), signature) {
		t.Error("Verification should fail with different message")
	}
}

func TestMLDSA87SignAndVerify(t *testing.T) {
	signer, err := NewMLDSA87Signer()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Test message for ML-DSA-87")

	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !signer.Verify(message, signature) {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	if signer.Verify([]byte("Different message"), signature) {
		t.Error("Verification should fail with different message")
	}
}

func TestNewMLDSASigner(t *testing.T) {
	tests := []struct {
		level       int
		expectError bool
		algorithm   string
	}{
		{44, false, "ML-DSA-44"},
		{65, false, "ML-DSA-65"},
		{87, false, "ML-DSA-87"},
		{128, true, ""}, // Invalid level
		{0, true, ""},   // Invalid level
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Level_%d", tt.level), func(t *testing.T) {
			signer, err := NewMLDSASigner(tt.level)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if signer.Algorithm() != tt.algorithm {
					t.Errorf("Expected algorithm %s, got %s", tt.algorithm, signer.Algorithm())
				}
			}
		})
	}
}

func TestVerifyMLDSASignature(t *testing.T) {
	// Test ML-DSA-65 verification with public key
	signer, err := NewMLDSA65Signer()
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	message := []byte("Test message")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	publicKey := signer.PublicKey()

	// Verify using public key bytes
	valid, err := VerifyMLDSASignature(publicKey, message, signature, 65)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test with wrong level (signature length mismatch should return false, not error)
	valid, err = VerifyMLDSASignature(publicKey, message, signature, 44)
	if err != nil {
		t.Errorf("Unexpected error when using wrong security level: %v", err)
	}
	if valid {
		t.Error("Expected verification to fail with wrong security level")
	}

	// Test with invalid level
	_, err = VerifyMLDSASignature(publicKey, message, signature, 999)
	if err == nil {
		t.Error("Expected error with invalid security level")
	}
}

func TestProviderGenerateSigner(t *testing.T) {
	tests := []struct {
		name             string
		provider         CryptoProvider
		expectedAlgorithm string
	}{
		{"Classical", NewClassicalProvider(), "ECDSA-P256"},
		{"MLKEM512", NewMLKEM512Provider(), "ML-DSA-44"},
		{"MLKEM768", NewMLKEM768Provider(), "ML-DSA-65"},
		{"MLKEM1024", NewMLKEM1024Provider(), "ML-DSA-87"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := tt.provider.GenerateSigner()
			if err != nil {
				t.Fatalf("Failed to generate signer: %v", err)
			}

			if signer.Algorithm() != tt.expectedAlgorithm {
				t.Errorf("Expected algorithm %s, got %s", tt.expectedAlgorithm, signer.Algorithm())
			}

			// Test sign and verify
			message := []byte("Test message")
			signature, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			if !signer.Verify(message, signature) {
				t.Error("Signature verification failed")
			}
		})
	}
}

// Benchmarks for ML-DSA

func BenchmarkMLDSA44Sign(b *testing.B) {
	signer, err := NewMLDSA44Signer()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSA65Sign(b *testing.B) {
	signer, err := NewMLDSA65Signer()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSA87Sign(b *testing.B) {
	signer, err := NewMLDSA87Signer()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Benchmark message")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMLDSA65Verify(b *testing.B) {
	signer, err := NewMLDSA65Signer()
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Benchmark message")
	signature, err := signer.Sign(message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = signer.Verify(message, signature)
	}
}
