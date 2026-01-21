package pqc

import (
	"fmt"
)

// NewProvider creates a new CryptoProvider based on the mode and security level
func NewProvider(mode CryptoMode, securityLevel PQCSecurityLevel) (CryptoProvider, error) {
	if !mode.IsValid() {
		return nil, fmt.Errorf("invalid crypto mode: %s", mode)
	}

	switch mode {
	case ModeClassical:
		return NewClassicalProvider(), nil

	case ModePQC:
		if !securityLevel.IsValid() {
			return nil, fmt.Errorf("invalid PQC security level: %d", securityLevel)
		}

		switch securityLevel {
		case SecurityLevel128:
			return NewMLKEM512Provider(), nil
		case SecurityLevel192:
			return NewMLKEM768Provider(), nil
		case SecurityLevel256:
			return NewMLKEM1024Provider(), nil
		default:
			return nil, fmt.Errorf("unsupported PQC security level: %d", securityLevel)
		}

	case ModeAuto:
		// For auto mode, start with ML-KEM-768 as the default
		// This can be negotiated during handshake
		return NewMLKEM768Provider(), nil

	default:
		return nil, fmt.Errorf("unsupported crypto mode: %s", mode)
	}
}

// GetProviderForSecurityLevel returns a provider for the specified security level
// This is used when the security level needs to be changed during negotiation
func GetProviderForSecurityLevel(level int) (CryptoProvider, error) {
	switch level {
	case 128:
		return NewClassicalProvider(), nil
	case 512:
		return NewMLKEM512Provider(), nil
	case 768:
		return NewMLKEM768Provider(), nil
	case 1024:
		return NewMLKEM1024Provider(), nil
	default:
		return nil, fmt.Errorf("unsupported security level: %d", level)
	}
}
