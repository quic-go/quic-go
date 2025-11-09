package pqc

// CryptoMode defines the cryptographic mode for QUIC connections
type CryptoMode string

const (
	// ModeClassical uses traditional ECDH (X25519) and ECDSA
	ModeClassical CryptoMode = "classical"

	// ModePQC uses post-quantum cryptography (ML-KEM and ML-DSA)
	ModePQC CryptoMode = "pqc"

	// ModeAuto negotiates the best available mode with the peer
	ModeAuto CryptoMode = "auto"
)

// IsValid checks if the crypto mode is valid
func (m CryptoMode) IsValid() bool {
	switch m {
	case ModeClassical, ModePQC, ModeAuto:
		return true
	default:
		return false
	}
}

// String returns the string representation of the crypto mode
func (m CryptoMode) String() string {
	return string(m)
}

// PQCSecurityLevel defines the security level for PQC algorithms
type PQCSecurityLevel int

const (
	// SecurityLevel192 provides ~192-bit security (ML-KEM-768, ML-DSA-65)
	SecurityLevel192 PQCSecurityLevel = 768

	// SecurityLevel256 provides ~256-bit security (ML-KEM-1024, ML-DSA-87)
	SecurityLevel256 PQCSecurityLevel = 1024
)

// IsValid checks if the security level is valid
func (s PQCSecurityLevel) IsValid() bool {
	switch s {
	case SecurityLevel192, SecurityLevel256:
		return true
	default:
		return false
	}
}

// KEMLevel returns the KEM level (512, 768, or 1024)
func (s PQCSecurityLevel) KEMLevel() int {
	return int(s)
}

// DSALevel returns the DSA level (65 or 87)
func (s PQCSecurityLevel) DSALevel() int {
	switch s {
	case SecurityLevel192:
		return 65
	case SecurityLevel256:
		return 87
	default:
		return 65 // default to 192-bit security
	}
}
