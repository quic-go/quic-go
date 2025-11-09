# Post-Quantum Cryptography Migration Guide for quic-go

## Executive Summary

This document outlines a comprehensive strategy for migrating the quic-go implementation to support Post-Quantum Cryptography (PQC), specifically integrating NIST-standardized algorithms ML-KEM (Kyber) and ML-DSA (Dilithium). Based on the theoretical foundations from the TCC document and current research on PQC implementations in QUIC, this guide provides actionable steps for achieving quantum resistance while maintaining the protocol's performance characteristics.

## 1. Introduction

### 1.1 Context and Motivation

The QUIC protocol (RFC 9000), implemented in quic-go, currently relies on classical cryptographic algorithms such as RSA and ECDSA for authentication and ECDH for key exchange. While these algorithms are secure against classical computers, they are vulnerable to attacks from sufficiently powerful quantum computers using Shor's algorithm.

### 1.2 The Quantum Threat

Quantum computers capable of running Shor's algorithm can efficiently:
- Factor large integers (breaking RSA)
- Solve discrete logarithm problems (breaking ECC/ECDSA)
- Compromise current QUIC/TLS 1.3 security

The timeline for quantum computers reaching this capability is uncertain, but the "harvest now, decrypt later" threat means sensitive data encrypted today could be compromised in the future.

### 1.3 NIST Post-Quantum Standards

In 2024, NIST finalized three post-quantum cryptographic standards:

- **FIPS 203 (ML-KEM)**: Module-Lattice-Based Key-Encapsulation Mechanism
  - Based on CRYSTALS-Kyber
  - Three security levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - Primary algorithm for key establishment

- **FIPS 204 (ML-DSA)**: Module-Lattice-Based Digital Signature Algorithm
  - Based on CRYSTALS-Dilithium
  - Three security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Primary algorithm for digital signatures

- **FIPS 205 (SLH-DSA)**: Stateless Hash-Based Digital Signature Algorithm
  - Based on SPHINCS+
  - Backup signature scheme (not recommended for QUIC due to performance)

## 2. Current State Analysis

### 2.1 quic-go Cryptographic Dependencies

The quic-go implementation currently depends on:

**TLS 1.3 Integration** (`internal/handshake/`):
- Uses Go's `crypto/tls` package with qtls extensions
- ECDH for key exchange (X25519, P-256, P-384)
- ECDSA/RSA for digital signatures
- Integrated handshake with QUIC transport

**Key Components**:
- `internal/handshake/crypto_setup.go`: TLS handshake coordination
- `internal/handshake/cipher_suite.go`: Cipher suite management
- `internal/qtls/`: Modified TLS implementation for QUIC

### 2.2 Current Handshake Flow

```
Client                                              Server
   |                                                   |
   |---- Initial[CH] ---------------------------------→|
   |                                                   |
   |←--- Initial[SH], Handshake[EE, CERT, CV, FIN] ---|
   |                                                   |
   |---- Handshake[FIN] ------------------------------→|
   |                                                   |
   |←--- 1-RTT[DONE] ----------------------------------|
```

Where:
- CH = ClientHello (includes supported key exchange algorithms)
- SH = ServerHello (selected key exchange algorithm)
- EE = EncryptedExtensions
- CERT = Certificate (server certificate with public key)
- CV = CertificateVerify (signature over handshake)
- FIN = Finished

## 3. Post-Quantum Cryptography Impact on QUIC

### 3.1 Cryptographic Object Size Comparison

| Algorithm | Public Key | Secret Key | Ciphertext/Signature | Security Level |
|-----------|-----------|------------|---------------------|----------------|
| **Key Exchange** |
| X25519 (classical) | 32 B | 32 B | 32 B | ~128-bit |
| ML-KEM-512 | 800 B | 1,632 B | 768 B | ~128-bit |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B | ~192-bit |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B | ~256-bit |
| **Signatures** |
| ECDSA P-256 | 64 B | 32 B | 64 B | ~128-bit |
| RSA-3072 | 384 B | 384 B | 384 B | ~128-bit |
| ML-DSA-44 | 1,312 B | 2,560 B | 2,420 B | ~128-bit |
| ML-DSA-65 | 1,952 B | 4,032 B | 3,309 B | ~192-bit |
| ML-DSA-87 | 2,592 B | 4,896 B | 4,627 B | ~256-bit |

### 3.2 Performance Characteristics

Recent research (Kempf et al., 2024) shows:

**Computational Overhead**:
- ML-KEM: **Faster** than classical ECDH in key generation and encapsulation
- ML-DSA: Comparable performance to RSA-3072, faster than RSA for equivalent security
- Overall: < 5% latency increase on modern server hardware

**Bandwidth Overhead**:
- Certificate size increases: ~2-4 KB per certificate
- Handshake messages can exceed UDP MTU (1200-1500 bytes)
- Potential for additional round trips due to fragmentation

**QUIC-Specific Concerns**:
1. **Anti-Amplification Limits**: QUIC limits server responses to 3x client data before address validation
2. **Initial Packet Size**: Larger certificates may require multiple Initial packets
3. **0-RTT Compatibility**: PQC impacts on 0-RTT handshake timing

### 3.3 Advantages of QUIC for PQC

Research shows QUIC outperforms TCP/TLS with PQC:
- 52% faster than TCP/TLS with RSA
- 2.5%+ faster with Dilithium algorithms
- 32.8%+ faster with Falcon algorithms

Reasons:
- Reduced handshake overhead (combined transport/crypto)
- Better handling of packet loss with per-stream recovery
- Native support for 0-RTT reducing total round trips

## 4. Migration Strategy

### 4.1 Dual-Support Approach

This implementation will support **both classical and PQC cryptography independently**, allowing users to choose their preferred cryptographic suite via configuration. This approach provides:

**Key Principles**:
- **Independent Implementations**: Classical (X25519/ECDSA) and PQC (ML-KEM/ML-DSA) run as separate, complete implementations
- **Configuration-Based Selection**: Users can easily switch between classical and PQC via config flags
- **No Hybrid Overhead**: Unlike hybrid mode, this avoids the computational and bandwidth costs of running both algorithms simultaneously
- **Clear Migration Path**: Allows gradual adoption without forcing all users to adopt PQC immediately
- **Algorithm Negotiation**: Client and server negotiate which approach to use during handshake

**Supported Modes**:
1. **Classical Mode** (Default): Uses X25519 + ECDSA/RSA
2. **PQC Mode**: Uses ML-KEM + ML-DSA
3. **Auto Mode**: Client advertises both; server selects based on its configuration

### 4.2 Implementation Phases

**Phase 1: Add PQC Support (Months 1-4)**
- Implement ML-KEM and ML-DSA alongside existing classical crypto
- Add configuration options to select crypto suite
- Maintain classical as default for backward compatibility
- Comprehensive testing of PQC mode

**Phase 2: Production Testing (Months 4-8)**
- Opt-in PQC deployment for early adopters
- Monitor performance and compatibility
- Collect metrics from both modes
- Refine implementation based on feedback

**Phase 3: Increased Adoption (Months 8-16)**
- Encourage PQC adoption for quantum-sensitive applications
- Maintain both implementations in parallel
- Update documentation and best practices
- Consider making PQC default for new deployments

**Phase 4: Long-term Support (Months 16+)**
- Continue supporting both modes indefinitely
- Add new PQC algorithms as they are standardized
- Provide migration tools and guidance
- Eventually deprecate classical only when quantum threat becomes imminent

### 4.3 Recommended Algorithm Selection

Based on security level and performance analysis:

**Classical Mode (Current Default)**:
- **Key Exchange**: X25519
- **Signatures**: ECDSA P-256 or RSA-3072
- **Use Case**: Current production deployments, legacy compatibility

**PQC Mode - General Use (Recommended)**:
- **Key Exchange**: ML-KEM-768
- **Signatures**: ML-DSA-65
- **Use Case**: Quantum-resistant security, balanced performance
- **Security Level**: ~192-bit quantum security

**PQC Mode - High Security**:
- **Key Exchange**: ML-KEM-1024
- **Signatures**: ML-DSA-87
- **Use Case**: Long-term sensitive data, high-security requirements
- **Security Level**: ~256-bit quantum security

**PQC Mode - Performance Priority**:
- **Key Exchange**: ML-KEM-512
- **Signatures**: ML-DSA-44
- **Use Case**: Resource-constrained environments
- **Security Level**: ~128-bit quantum security

## 5. Implementation Roadmap

### 5.1 Dependencies and Prerequisites

**Available PQC Implementations for Go**:

#### 1. **Go Standard Library (Recommended for Production)**

Go 1.23+ and 1.24+ include native PQC support:

```go
// Go 1.24+: Native ML-KEM support
import "crypto/mlkem"

// Go 1.23+: X25519Kyber768 hybrid for TLS
import "crypto/tls"
```

**Features**:
- ✅ Production-ready and FIPS 140-3 validated
- ✅ ML-KEM-768 and ML-KEM-1024 support (FIPS 203)
- ✅ Hybrid X25519MLKEM768 in TLS
- ✅ Pure Go implementation
- ✅ Security audited by Trail of Bits
- ⚠️ ML-DSA support planned for Go 1.26+

**Status**: **RECOMMENDED** - Use for ML-KEM key exchange

**Usage**:
```go
// ML-KEM-768 key generation (Go 1.24+)
encapsulationKey, decapsulationKey, err := mlkem.GenerateKey768()

// Client: Encapsulate shared secret
ciphertext, sharedSecret := mlkem.Encapsulate768(encapsulationKey)

// Server: Decapsulate shared secret
sharedSecret, err := mlkem.Decapsulate768(decapsulationKey, ciphertext)
```

#### 2. **Cloudflare CIRCL Library**

CIRCL (Cloudflare Interoperable Reusable Cryptographic Library) is production-ready:

```go
import "github.com/cloudflare/circl/kem/kyber/kyber768"
import "github.com/cloudflare/circl/sign/dilithium/mode3"
import "github.com/cloudflare/circl/sign/slhdsa/shake128f"
```

**Supported Algorithms**:

**Key Encapsulation (KEMs)**:
- ✅ Kyber512, Kyber768, Kyber1024
- ✅ ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
- ✅ Hybrid: X25519Kyber768, P256Kyber768

**Digital Signatures**:
- ✅ Dilithium Mode2, Mode3, Mode5
- ✅ ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
- ✅ SLH-DSA (FIPS 205) - 12 parameter sets
- ✅ Hybrid: EdDilithium2, EdDilithium3

**Status**: **RECOMMENDED** - Most complete PQC library for Go

**Package Reference**:
```go
// ML-KEM (FIPS 203)
import (
    "github.com/cloudflare/circl/kem/mlkem/mlkem512"
    "github.com/cloudflare/circl/kem/mlkem/mlkem768"
    "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// ML-DSA (FIPS 204)
import (
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
    "github.com/cloudflare/circl/sign/mldsa/mldsa65"
    "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// SLH-DSA (FIPS 205)
import (
    "github.com/cloudflare/circl/sign/slhdsa/shake128f"
    "github.com/cloudflare/circl/sign/slhdsa/shake128s"
    "github.com/cloudflare/circl/sign/slhdsa/shake256f"
    "github.com/cloudflare/circl/sign/slhdsa/shake256s"
)
```

#### 3. **filippo.io/mlkem768**

Pure-Go ML-KEM-768 implementation by Filippo Valsorda:

```go
import "filippo.io/mlkem768"
```

**Features**:
- ✅ Pure Go, no dependencies
- ✅ Optimized for correctness and readability
- ✅ Designed for upstreaming to Go standard library
- ⚠️ Only ML-KEM-768 (no 512 or 1024)

**Status**: Good for ML-KEM-768 specifically, but CIRCL offers more options

#### 4. **Open Quantum Safe (liboqs-go)**

Go bindings for the liboqs C library:

```go
import "github.com/open-quantum-safe/liboqs-go/oqs"
```

**Features**:
- ✅ Comprehensive algorithm support (30+ algorithms)
- ✅ Includes experimental/research algorithms
- ⚠️ C dependency (requires CGO)
- ⚠️ Primarily for research, not recommended for production

**Supported KEMs**: ML-KEM, HQC, BIKE, Classic McEliece, FrodoKEM, NTRU, SABER
**Supported Signatures**: ML-DSA, SLH-DSA, FALCON, MAYO, CROSS

**Status**: Use for research or if you need algorithms not in CIRCL

### 5.1.1 Recommended Implementation Choice

**For quic-go PQC Migration**:

1. **Key Exchange**: Use **Go 1.24 `crypto/mlkem`** or **CIRCL ML-KEM**
   - Go standard library is preferred for ML-KEM
   - CIRCL as fallback or for additional KEM variants

2. **Signatures**: Use **CIRCL ML-DSA** (until Go 1.26+)
   - Most production-ready ML-DSA implementation
   - FIPS 204 compliant
   - Well-tested and maintained

3. **Optional**: Support **SLH-DSA** from CIRCL as backup signature scheme

**Installation**:
```bash
# For ML-KEM: Ensure Go 1.24+
go version  # Should be >= 1.24

# For ML-DSA and comprehensive support
go get github.com/cloudflare/circl@latest
```

### 5.1.2 Complete Algorithm Matrix

**Key Encapsulation Mechanisms (KEMs)**:

| Algorithm | NIST Standard | Security Level | Go Std Lib | CIRCL | liboqs | Recommended |
|-----------|---------------|----------------|------------|-------|--------|-------------|
| ML-KEM-512 | FIPS 203 | ~128-bit | Go 1.24 | ✅ | ✅ | ✅ |
| ML-KEM-768 | FIPS 203 | ~192-bit | Go 1.24 | ✅ | ✅ | ✅ Primary |
| ML-KEM-1024 | FIPS 203 | ~256-bit | Go 1.24 | ✅ | ✅ | ✅ |
| Classic McEliece | Round 4 | ~256-bit | ❌ | ❌ | ✅ | ⚠️ Research |
| HQC | Round 4 (2025) | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Future |
| BIKE | Round 4 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |
| FrodoKEM | Round 3 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |
| NTRU | Round 3 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |
| SABER | Round 3 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |

**Digital Signature Algorithms**:

| Algorithm | NIST Standard | Security Level | Go Std Lib | CIRCL | liboqs | Recommended |
|-----------|---------------|----------------|------------|-------|--------|-------------|
| ML-DSA-44 | FIPS 204 | ~128-bit | Go 1.26 | ✅ | ✅ | ✅ |
| ML-DSA-65 | FIPS 204 | ~192-bit | Go 1.26 | ✅ | ✅ | ✅ Primary |
| ML-DSA-87 | FIPS 204 | ~256-bit | Go 1.26 | ✅ | ✅ | ✅ |
| SLH-DSA | FIPS 205 | Various | ❌ | ✅ (12 sets) | ✅ | ✅ Backup |
| FALCON-512 | FIPS 206 (draft) | ~128-bit | ❌ | ❌ | ✅ | ⚠️ Future |
| FALCON-1024 | FIPS 206 (draft) | ~256-bit | ❌ | ❌ | ✅ | ⚠️ Future |
| MAYO | Round 1 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |
| CROSS | Round 1 | ~128/192/256 | ❌ | ❌ | ✅ | ⚠️ Research |

**Legend**:
- ✅ Production-ready
- ⚠️ Research/experimental or future standard
- ❌ Not available

**Notes**:
- **Primary**: ML-KEM-768 + ML-DSA-65 (balanced security/performance)
- **High Security**: ML-KEM-1024 + ML-DSA-87
- **Performance**: ML-KEM-512 + ML-DSA-44
- **Backup Signature**: SLH-DSA (stateless hash-based, larger signatures)

### 5.1.3 Algorithm Selection Guide

**For General Use (Recommended)**:
```go
import (
    "crypto/mlkem"  // Go 1.24+ for ML-KEM-768
    "github.com/cloudflare/circl/sign/mldsa/mldsa65"  // For ML-DSA-65
)
```
- **KEM**: ML-KEM-768 (~192-bit quantum security)
- **Signature**: ML-DSA-65 (~192-bit quantum security)
- **Rationale**: Best security/performance tradeoff

**For High-Security Applications**:
```go
import (
    "crypto/mlkem"  // Go 1.24+ for ML-KEM-1024
    "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)
```
- **KEM**: ML-KEM-1024 (~256-bit quantum security)
- **Signature**: ML-DSA-87 (~256-bit quantum security)

**For Performance-Critical Applications**:
```go
import (
    "crypto/mlkem"  // Go 1.24+ for ML-KEM-512
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)
```
- **KEM**: ML-KEM-512 (~128-bit quantum security)
- **Signature**: ML-DSA-44 (~128-bit quantum security)
- **Note**: Smallest keys/signatures, fastest operations

**With Backup Signature Scheme**:
```go
import (
    "crypto/mlkem"
    "github.com/cloudflare/circl/sign/mldsa/mldsa65"
    "github.com/cloudflare/circl/sign/slhdsa/shake256s"  // Backup
)
```
- Use SLH-DSA as backup if lattice-based crypto has issues
- SLH-DSA is hash-based (different security assumption)

### 5.2 Architecture Changes

**Component Modifications**:

1. **Handshake Layer** (`internal/handshake/`):
   ```
   internal/handshake/
   ├── crypto_setup.go          # Add PQC algorithm negotiation
   ├── crypto_setup_tls.go      # TLS 1.3 integration (classical)
   ├── crypto_setup_pqc.go      # New: PQC-specific setup
   ├── cipher_suite.go          # Extend with PQC cipher suites
   └── pqc/                     # New directory
       ├── ml_kem.go            # ML-KEM key exchange
       ├── ml_dsa.go            # ML-DSA signatures
       ├── provider.go          # Crypto provider interface
       └── negotiation.go       # Algorithm negotiation
   ```

2. **Certificate Handling**:
   ```
   internal/handshake/
   └── pqc/
       ├── certificate.go       # PQC certificate parsing
       ├── certificate_chain.go # Handle larger cert chains
       └── compression.go       # Optional: certificate compression
   ```

3. **Protocol Extensions**:
   ```
   internal/protocol/
   └── pqc_params.go            # PQC-specific parameters
   ```

### 5.3 Code Changes Overview

**A. TLS Cipher Suite Registration**

Create new file `internal/handshake/pqc/cipher_suites.go`:

```go
package pqc

import (
    "crypto/tls"
    "github.com/quic-go/quic-go/internal/qtls"
)

// PQC Cipher Suite IDs (to be registered with IANA)
const (
    TLS_AES_128_GCM_SHA256_MLKEM768       uint16 = 0xTBD1
    TLS_AES_256_GCM_SHA384_MLKEM1024      uint16 = 0xTBD2
    TLS_CHACHA20_POLY1305_SHA256_MLKEM768 uint16 = 0xTBD3
)

// PQC Signature Algorithm IDs
const (
    SignatureAlgorithmMLDSA44 = 0xTBD4
    SignatureAlgorithmMLDSA65 = 0xTBD5
    SignatureAlgorithmMLDSA87 = 0xTBD6
)

// Crypto Mode Type
type CryptoMode int

const (
    CryptoModeClassical CryptoMode = iota
    CryptoModePQC
    CryptoModeAuto  // Negotiate based on peer capabilities
)
```

**B. ML-KEM Key Exchange Implementation**

Create new file `internal/handshake/pqc/ml_kem.go`:

```go
package pqc

import (
    "crypto/mlkem"  // Go 1.24+
    "fmt"

    // Alternative: use CIRCL if Go < 1.24
    // "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// MLKEMKeyExchange provides ML-KEM key encapsulation
type MLKEMKeyExchange struct {
    level          int  // 512, 768, or 1024
    encapKey       *mlkem.EncapsulationKey768
    decapKey       *mlkem.DecapsulationKey768
}

// NewMLKEM768KeyExchange creates a new ML-KEM-768 key exchange
func NewMLKEM768KeyExchange() (*MLKEMKeyExchange, error) {
    // Using Go 1.24+ crypto/mlkem
    encapKey, decapKey, err := mlkem.GenerateKey768()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-KEM-768 keypair: %w", err)
    }

    return &MLKEMKeyExchange{
        level:    768,
        encapKey: encapKey,
        decapKey: decapKey,
    }, nil
}

// NewMLKEM512KeyExchange creates ML-KEM-512 (lower security, faster)
func NewMLKEM512KeyExchange() (*MLKEMKeyExchange, error) {
    encapKey, decapKey, err := mlkem.GenerateKey512()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-KEM-512 keypair: %w", err)
    }

    return &MLKEMKeyExchange{
        level:    512,
        encapKey: encapKey,
        decapKey: decapKey,
    }, nil
}

// NewMLKEM1024KeyExchange creates ML-KEM-1024 (higher security)
func NewMLKEM1024KeyExchange() (*MLKEMKeyExchange, error) {
    encapKey, decapKey, err := mlkem.GenerateKey1024()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-KEM-1024 keypair: %w", err)
    }

    return &MLKEMKeyExchange{
        level:    1024,
        encapKey: encapKey,
        decapKey: decapKey,
    }, nil
}

// PublicKey returns the encapsulation key for transmission
func (k *MLKEMKeyExchange) PublicKey() []byte {
    return k.encapKey.Bytes()
}

// Encapsulate creates a shared secret (client-side)
func (k *MLKEMKeyExchange) Encapsulate(peerPublicKeyBytes []byte) (ciphertext, sharedSecret []byte, err error) {
    // Parse peer's encapsulation key
    peerEncapKey, err := mlkem.ParseEncapsulationKey768(peerPublicKeyBytes)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to parse peer public key: %w", err)
    }

    // Encapsulate to create shared secret and ciphertext
    ciphertext, sharedSecret = mlkem.Encapsulate768(peerEncapKey)

    return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret (server-side)
func (k *MLKEMKeyExchange) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
    sharedSecret, err = mlkem.Decapsulate768(k.decapKey, ciphertext)
    if err != nil {
        return nil, fmt.Errorf("decapsulation failed: %w", err)
    }

    return sharedSecret, nil
}

// DeriveSharedSecret implements KeyExchange interface
func (k *MLKEMKeyExchange) DeriveSharedSecret(peerPublicKey []byte, isClient bool) ([]byte, error) {
    if isClient {
        // Client encapsulates
        _, sharedSecret, err := k.Encapsulate(peerPublicKey)
        return sharedSecret, err
    }
    // Server decapsulates (peerPublicKey is actually the ciphertext in this case)
    return k.Decapsulate(peerPublicKey)
}
```

**Alternative implementation using CIRCL** (for Go < 1.24 or additional features):

```go
package pqc

import (
    "fmt"
    "github.com/cloudflare/circl/kem"
    "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type MLKEMKeyExchangeCIRCL struct {
    scheme    kem.Scheme
    publicKey kem.PublicKey
    secretKey kem.PrivateKey
}

func NewMLKEM768KeyExchangeCIRCL() (*MLKEMKeyExchangeCIRCL, error) {
    scheme := mlkem768.Scheme()
    pub, priv, err := scheme.GenerateKeyPair()
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-KEM-768 keypair: %w", err)
    }

    return &MLKEMKeyExchangeCIRCL{
        scheme:    scheme,
        publicKey: pub,
        secretKey: priv,
    }, nil
}

func (k *MLKEMKeyExchangeCIRCL) PublicKey() []byte {
    pub, _ := k.publicKey.MarshalBinary()
    return pub
}

func (k *MLKEMKeyExchangeCIRCL) Encapsulate(peerPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
    pub, err := k.scheme.UnmarshalBinaryPublicKey(peerPublicKey)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to unmarshal peer public key: %w", err)
    }

    ct, ss, err := k.scheme.Encapsulate(pub)
    if err != nil {
        return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
    }

    return ct, ss, nil
}

func (k *MLKEMKeyExchangeCIRCL) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
    ss, err := k.scheme.Decapsulate(k.secretKey, ciphertext)
    if err != nil {
        return nil, fmt.Errorf("decapsulation failed: %w", err)
    }

    return ss, nil
}
```

**C. Crypto Provider Interface**

Create new file `internal/handshake/pqc/provider.go`:

```go
package pqc

// CryptoProvider defines the interface for cryptographic operations
// This allows easy switching between classical and PQC implementations
type CryptoProvider interface {
    // Key exchange operations
    GenerateKeyPair() (KeyExchange, error)

    // Signature operations
    GenerateSigner() (Signer, error)

    // Provider metadata
    Mode() CryptoMode
    KeyExchangeAlgorithm() string
    SignatureAlgorithm() string
}

// KeyExchange interface for both classical and PQC key exchange
type KeyExchange interface {
    PublicKey() []byte
    DeriveSharedSecret(peerPublicKey []byte, isClient bool) ([]byte, error)
}

// Signer interface for both classical and PQC signatures
type Signer interface {
    PublicKey() []byte
    Sign(message []byte) ([]byte, error)
    Verify(message, signature []byte) bool
}

// Classical crypto provider
type ClassicalProvider struct{}

func NewClassicalProvider() *ClassicalProvider {
    return &ClassicalProvider{}
}

func (p *ClassicalProvider) Mode() CryptoMode {
    return CryptoModeClassical
}

func (p *ClassicalProvider) KeyExchangeAlgorithm() string {
    return "X25519"
}

func (p *ClassicalProvider) SignatureAlgorithm() string {
    return "ECDSA-P256"
}

func (p *ClassicalProvider) GenerateKeyPair() (KeyExchange, error) {
    // Return X25519 key exchange implementation
    return NewX25519KeyExchange()
}

func (p *ClassicalProvider) GenerateSigner() (Signer, error) {
    // Return ECDSA signer implementation
    return NewECDSASigner()
}

// PQC crypto provider
type PQCProvider struct {
    kemLevel int // 512, 768, or 1024
    dsaLevel int // 44, 65, or 87
}

func NewPQCProvider(kemLevel, dsaLevel int) *PQCProvider {
    return &PQCProvider{
        kemLevel: kemLevel,
        dsaLevel: dsaLevel,
    }
}

func (p *PQCProvider) Mode() CryptoMode {
    return CryptoModePQC
}

func (p *PQCProvider) KeyExchangeAlgorithm() string {
    return fmt.Sprintf("ML-KEM-%d", p.kemLevel)
}

func (p *PQCProvider) SignatureAlgorithm() string {
    return fmt.Sprintf("ML-DSA-%d", p.dsaLevel)
}

func (p *PQCProvider) GenerateKeyPair() (KeyExchange, error) {
    switch p.kemLevel {
    case 512:
        return NewMLKEM512KeyExchange()
    case 768:
        return NewMLKEM768KeyExchange()
    case 1024:
        return NewMLKEM1024KeyExchange()
    default:
        return nil, fmt.Errorf("unsupported KEM level: %d", p.kemLevel)
    }
}

func (p *PQCProvider) GenerateSigner() (Signer, error) {
    switch p.dsaLevel {
    case 44:
        return NewMLDSA44Signer()
    case 65:
        return NewMLDSA65Signer()
    case 87:
        return NewMLDSA87Signer()
    default:
        return nil, fmt.Errorf("unsupported DSA level: %d", p.dsaLevel)
    }
}
```

**D. Algorithm Negotiation**

Create new file `internal/handshake/pqc/negotiation.go`:

```go
package pqc

// SupportedAlgorithms represents the crypto algorithms supported by a peer
type SupportedAlgorithms struct {
    KeyExchangeAlgorithms []string
    SignatureAlgorithms   []string
}

// NegotiateCrypto determines which crypto mode to use based on:
// - Client preferences (advertised algorithms)
// - Server configuration
// - Mutual support
func NegotiateCrypto(
    clientSupport SupportedAlgorithms,
    serverConfig CryptoMode,
) (CryptoProvider, error) {
    // If server is in Classical mode, use classical
    if serverConfig == CryptoModeClassical {
        return NewClassicalProvider(), nil
    }

    // If server is in PQC mode, use PQC if client supports it
    if serverConfig == CryptoModePQC {
        if supportsPQC(clientSupport) {
            return NewPQCProvider(768, 65), nil // Default to ML-KEM-768/ML-DSA-65
        }
        return nil, fmt.Errorf("client does not support PQC but server requires it")
    }

    // Auto mode: prefer PQC if both support it, fallback to classical
    if serverConfig == CryptoModeAuto {
        if supportsPQC(clientSupport) {
            return NewPQCProvider(768, 65), nil
        }
        return NewClassicalProvider(), nil
    }

    return nil, fmt.Errorf("unknown crypto mode: %v", serverConfig)
}

func supportsPQC(support SupportedAlgorithms) bool {
    for _, kem := range support.KeyExchangeAlgorithms {
        if strings.HasPrefix(kem, "ML-KEM-") {
            return true
        }
    }
    return false
}
```

**E. ML-DSA Signature Integration**

Create new file `internal/handshake/pqc/ml_dsa.go`:

```go
package pqc

import (
    "crypto/rand"
    "fmt"

    // Use Cloudflare CIRCL for ML-DSA (until Go 1.26+)
    "github.com/cloudflare/circl/sign/mldsa/mldsa44"
    "github.com/cloudflare/circl/sign/mldsa/mldsa65"
    "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// MLDSASigner provides ML-DSA digital signatures
type MLDSASigner struct {
    level      int
    publicKey  []byte
    privateKey []byte
}

// NewMLDSA44Signer creates ML-DSA-44 (128-bit security)
func NewMLDSA44Signer() (*MLDSASigner, error) {
    pub, priv, err := mldsa44.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-DSA-44 keypair: %w", err)
    }

    pubBytes, err := pub.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    privBytes, err := priv.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal private key: %w", err)
    }

    return &MLDSASigner{
        level:      44,
        publicKey:  pubBytes,
        privateKey: privBytes,
    }, nil
}

// NewMLDSA65Signer creates ML-DSA-65 (192-bit security, recommended)
func NewMLDSA65Signer() (*MLDSASigner, error) {
    pub, priv, err := mldsa65.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-DSA-65 keypair: %w", err)
    }

    pubBytes, err := pub.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    privBytes, err := priv.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal private key: %w", err)
    }

    return &MLDSASigner{
        level:      65,
        publicKey:  pubBytes,
        privateKey: privBytes,
    }, nil
}

// NewMLDSA87Signer creates ML-DSA-87 (256-bit security)
func NewMLDSA87Signer() (*MLDSASigner, error) {
    pub, priv, err := mldsa87.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate ML-DSA-87 keypair: %w", err)
    }

    pubBytes, err := pub.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    privBytes, err := priv.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal private key: %w", err)
    }

    return &MLDSASigner{
        level:      87,
        publicKey:  pubBytes,
        privateKey: privBytes,
    }, nil
}

// PublicKey returns the public key bytes
func (s *MLDSASigner) PublicKey() []byte {
    return s.publicKey
}

// Sign creates a signature over the message
func (s *MLDSASigner) Sign(message []byte) ([]byte, error) {
    var priv interface{}
    var err error

    switch s.level {
    case 44:
        priv, err = mldsa44.NewPrivateKeyFromSeed(s.privateKey[:mldsa44.SeedSize])
    case 65:
        priv, err = mldsa65.NewPrivateKeyFromSeed(s.privateKey[:mldsa65.SeedSize])
    case 87:
        priv, err = mldsa87.NewPrivateKeyFromSeed(s.privateKey[:mldsa87.SeedSize])
    default:
        return nil, fmt.Errorf("unsupported ML-DSA level: %d", s.level)
    }

    if err != nil {
        return nil, fmt.Errorf("failed to reconstruct private key: %w", err)
    }

    var signature []byte
    switch s.level {
    case 44:
        signature = mldsa44.Sign(priv.(*mldsa44.PrivateKey), message)
    case 65:
        signature = mldsa65.Sign(priv.(*mldsa65.PrivateKey), message)
    case 87:
        signature = mldsa87.Sign(priv.(*mldsa87.PrivateKey), message)
    }

    return signature, nil
}

// Verify checks a signature over the message
func (s *MLDSASigner) Verify(message, signature []byte) bool {
    var pub interface{}
    var err error

    switch s.level {
    case 44:
        var pk mldsa44.PublicKey
        err = pk.UnmarshalBinary(s.publicKey)
        pub = &pk
    case 65:
        var pk mldsa65.PublicKey
        err = pk.UnmarshalBinary(s.publicKey)
        pub = &pk
    case 87:
        var pk mldsa87.PublicKey
        err = pk.UnmarshalBinary(s.publicKey)
        pub = &pk
    default:
        return false
    }

    if err != nil {
        return false
    }

    switch s.level {
    case 44:
        return mldsa44.Verify(pub.(*mldsa44.PublicKey), message, signature)
    case 65:
        return mldsa65.Verify(pub.(*mldsa65.PublicKey), message, signature)
    case 87:
        return mldsa87.Verify(pub.(*mldsa87.PublicKey), message, signature)
    }

    return false
}
```

**Optional: SLH-DSA Backup Signature** (hash-based, different security assumption):

```go
package pqc

import (
    "crypto/rand"
    "fmt"
    "github.com/cloudflare/circl/sign/slhdsa/shake256s"
)

type SLHDSASigner struct {
    publicKey  []byte
    privateKey []byte
}

func NewSLHDSASigner() (*SLHDSASigner, error) {
    pub, priv, err := shake256s.GenerateKey(rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("failed to generate SLH-DSA keypair: %w", err)
    }

    pubBytes, err := pub.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal public key: %w", err)
    }

    privBytes, err := priv.MarshalBinary()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal private key: %w", err)
    }

    return &SLHDSASigner{
        publicKey:  pubBytes,
        privateKey: privBytes,
    }, nil
}

func (s *SLHDSASigner) PublicKey() []byte {
    return s.publicKey
}

func (s *SLHDSASigner) Sign(message []byte) ([]byte, error) {
    var priv shake256s.PrivateKey
    if err := priv.UnmarshalBinary(s.privateKey); err != nil {
        return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
    }

    return shake256s.Sign(&priv, message), nil
}

func (s *SLHDSASigner) Verify(message, signature []byte) bool {
    var pub shake256s.PublicKey
    if err := pub.UnmarshalBinary(s.publicKey); err != nil {
        return false
    }

    return shake256s.Verify(&pub, message, signature)
}
```

**F. Integration with QUIC Handshake**

Modify `internal/handshake/crypto_setup.go`:

```go
package handshake

import (
    "github.com/quic-go/quic-go/internal/handshake/pqc"
    "github.com/quic-go/quic-go/internal/protocol"
)

type cryptoSetup struct {
    // ... existing fields ...

    // Crypto provider (classical or PQC)
    cryptoProvider pqc.CryptoProvider
    cryptoMode     pqc.CryptoMode

    // Key exchange and signature instances
    keyExchange    pqc.KeyExchange
    signer         pqc.Signer
}

func newCryptoSetup(
    // ... existing parameters ...
    cryptoMode pqc.CryptoMode,
) (*cryptoSetup, error) {
    cs := &cryptoSetup{
        // ... existing initialization ...
        cryptoMode: cryptoMode,
    }

    // Initialize crypto provider based on mode
    var provider pqc.CryptoProvider
    switch cryptoMode {
    case pqc.CryptoModeClassical:
        provider = pqc.NewClassicalProvider()
    case pqc.CryptoModePQC:
        provider = pqc.NewPQCProvider(768, 65) // ML-KEM-768, ML-DSA-65
    case pqc.CryptoModeAuto:
        // Will be determined during negotiation
        provider = pqc.NewClassicalProvider() // Default fallback
    default:
        return nil, fmt.Errorf("unsupported crypto mode: %v", cryptoMode)
    }

    cs.cryptoProvider = provider

    // Generate key pair
    keyEx, err := provider.GenerateKeyPair()
    if err != nil {
        return nil, fmt.Errorf("failed to generate key pair: %w", err)
    }
    cs.keyExchange = keyEx

    // Generate signer
    signer, err := provider.GenerateSigner()
    if err != nil {
        return nil, fmt.Errorf("failed to generate signer: %w", err)
    }
    cs.signer = signer

    return cs, nil
}

// NegotiateCrypto is called when we receive client's supported algorithms
func (cs *cryptoSetup) NegotiateCrypto(clientSupport pqc.SupportedAlgorithms) error {
    if cs.cryptoMode != pqc.CryptoModeAuto {
        // Already decided, no negotiation needed
        return nil
    }

    // Negotiate based on mutual support
    provider, err := pqc.NegotiateCrypto(clientSupport, cs.cryptoMode)
    if err != nil {
        return fmt.Errorf("crypto negotiation failed: %w", err)
    }

    // Update provider if negotiation resulted in different choice
    if provider.Mode() != cs.cryptoProvider.Mode() {
        cs.cryptoProvider = provider

        // Regenerate keys with new provider
        keyEx, err := provider.GenerateKeyPair()
        if err != nil {
            return fmt.Errorf("failed to generate key pair: %w", err)
        }
        cs.keyExchange = keyEx

        signer, err := provider.GenerateSigner()
        if err != nil {
            return fmt.Errorf("failed to generate signer: %w", err)
        }
        cs.signer = signer
    }

    return nil
}
```

### 5.4 Handling Anti-Amplification Limits

QUIC's anti-amplification protection limits server responses to 3x the client's initial data before address validation. Larger PQC certificates can trigger this limit.

**Solution Strategies**:

1. **Certificate Compression** (RFC 8879):
   ```go
   // Implement certificate compression
   func compressCertificate(cert []byte) []byte {
       // Use Brotli or Zstandard compression
       // Can reduce PQC certificate size by 20-30%
   }
   ```

2. **Cached Information Extension** (RFC 7924):
   - Cache server certificates on clients
   - Send certificate hash instead of full certificate
   - Reduces handshake size for repeated connections

3. **Increase Initial Packet Size**:
   ```go
   const (
       // Increase minimum initial packet size for PQC
       MinInitialPacketSize = 1500 // up from 1200
   )
   ```

4. **Split Certificate Chain**:
   - Send partial certificate in Initial packet
   - Complete certificate in Handshake packets
   - Requires careful implementation to maintain security

### 5.5 Configuration API

Add PQC configuration options to `Config`:

```go
// config.go
type Config struct {
    // ... existing fields ...

    // CryptoMode specifies which cryptographic approach to use
    // Options:
    //   - "classical": Use X25519/ECDSA (default, backward compatible)
    //   - "pqc": Use ML-KEM/ML-DSA (quantum-resistant)
    //   - "auto": Negotiate based on peer support (prefer PQC)
    CryptoMode string

    // PQCKeyExchangeLevel specifies the ML-KEM security level
    // Valid values: 512, 768 (default), 1024
    // Only used when CryptoMode is "pqc" or "auto"
    PQCKeyExchangeLevel int

    // PQCSignatureLevel specifies the ML-DSA security level
    // Valid values: 44, 65 (default), 87
    // Only used when CryptoMode is "pqc" or "auto"
    PQCSignatureLevel int
}

// Default configuration (classical mode for backward compatibility)
func defaultConfig() *Config {
    return &Config{
        CryptoMode:          "classical",
        PQCKeyExchangeLevel: 768,
        PQCSignatureLevel:   65,
    }
}

// Example: Enable PQC mode
func examplePQCConfig() *Config {
    return &Config{
        CryptoMode:          "pqc",
        PQCKeyExchangeLevel: 768,  // ML-KEM-768
        PQCSignatureLevel:   65,   // ML-DSA-65
    }
}

// Example: Auto-negotiate (prefer PQC, fallback to classical)
func exampleAutoConfig() *Config {
    return &Config{
        CryptoMode:          "auto",
        PQCKeyExchangeLevel: 768,
        PQCSignatureLevel:   65,
    }
}
```

### 5.6 Testing Strategy

**Unit Tests**:
```go
// internal/handshake/pqc/ml_kem_test.go
func TestMLKEMKeyExchange(t *testing.T) {
    // Test key generation
    keyEx, err := NewMLKEM768KeyExchange()
    require.NoError(t, err)

    // Test encapsulation/decapsulation
    pub := keyEx.PublicKey()
    ct, ss1, err := keyEx.Encapsulate(pub)
    require.NoError(t, err)

    ss2, err := keyEx.Decapsulate(ct)
    require.NoError(t, err)

    // Shared secrets should match
    require.Equal(t, ss1, ss2)
}
```

**Integration Tests**:
```go
// integrationtests/self/pqc_test.go

// Test classical mode (default)
func TestClassicalHandshake(t *testing.T) {
    server := startServer(t, &quic.Config{
        CryptoMode: "classical",
    })
    defer server.Close()

    config := &quic.Config{
        CryptoMode: "classical",
    }

    conn, err := quic.DialAddr(server.Addr(), nil, config)
    require.NoError(t, err)
    defer conn.CloseWithError(0, "")

    state := conn.ConnectionState()
    require.Equal(t, "X25519", state.KeyExchangeAlgorithm)
}

// Test PQC mode
func TestPQCHandshake(t *testing.T) {
    server := startServer(t, &quic.Config{
        CryptoMode:          "pqc",
        PQCKeyExchangeLevel: 768,
        PQCSignatureLevel:   65,
    })
    defer server.Close()

    config := &quic.Config{
        CryptoMode:          "pqc",
        PQCKeyExchangeLevel: 768,
        PQCSignatureLevel:   65,
    }

    conn, err := quic.DialAddr(server.Addr(), nil, config)
    require.NoError(t, err)
    defer conn.CloseWithError(0, "")

    state := conn.ConnectionState()
    require.Equal(t, "ML-KEM-768", state.KeyExchangeAlgorithm)
    require.Equal(t, "ML-DSA-65", state.SignatureAlgorithm)
}

// Test auto-negotiation
func TestAutoNegotiation(t *testing.T) {
    tests := []struct {
        name         string
        serverMode   string
        clientMode   string
        expectedKEM  string
    }{
        {
            name:        "Both support PQC",
            serverMode:  "auto",
            clientMode:  "auto",
            expectedKEM: "ML-KEM-768", // Should prefer PQC
        },
        {
            name:        "Client classical only",
            serverMode:  "auto",
            clientMode:  "classical",
            expectedKEM: "X25519", // Should fallback
        },
        {
            name:        "Server prefers PQC, client supports both",
            serverMode:  "pqc",
            clientMode:  "auto",
            expectedKEM: "ML-KEM-768",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            server := startServer(t, &quic.Config{
                CryptoMode: tt.serverMode,
            })
            defer server.Close()

            conn, err := quic.DialAddr(server.Addr(), nil, &quic.Config{
                CryptoMode: tt.clientMode,
            })
            require.NoError(t, err)
            defer conn.CloseWithError(0, "")

            state := conn.ConnectionState()
            require.Equal(t, tt.expectedKEM, state.KeyExchangeAlgorithm)
        })
    }
}

// Test backward compatibility
func TestBackwardCompatibility(t *testing.T) {
    // Old client (no PQC support) connecting to new server (PQC capable)
    server := startServer(t, &quic.Config{
        CryptoMode: "auto", // Server supports both
    })
    defer server.Close()

    // Simulate old client with classical-only
    config := &quic.Config{
        CryptoMode: "classical",
    }

    conn, err := quic.DialAddr(server.Addr(), nil, config)
    require.NoError(t, err)
    defer conn.CloseWithError(0, "")

    // Should successfully connect using classical crypto
    state := conn.ConnectionState()
    require.Equal(t, "X25519", state.KeyExchangeAlgorithm)
}
```

**Performance Benchmarks**:
```go
// internal/handshake/pqc/benchmark_test.go
func BenchmarkMLKEMKeyGeneration(b *testing.B) {
    for i := 0; i < b.N; i++ {
        _, err := NewMLKEM768KeyExchange()
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkClassicalHandshake(b *testing.B) {
    // Benchmark classical handshake
}

func BenchmarkPQCHandshake(b *testing.B) {
    // Benchmark PQC handshake
}

func BenchmarkHandshakeComparison(b *testing.B) {
    modes := []string{"classical", "pqc"}

    for _, mode := range modes {
        b.Run(mode, func(b *testing.B) {
            config := &quic.Config{
                CryptoMode: mode,
            }
            // Benchmark handshake with specific mode
        })
    }
}
```

## 6. Performance Optimization

### 6.1 Computational Optimizations

1. **Hardware Acceleration**:
   - Use AVX2/AVX-512 instructions where available
   - Leverage ARM NEON on ARM platforms
   - Consider: github.com/cloudflare/circl (has optimized implementations)

2. **Precomputation**:
   ```go
   // Precompute and cache PQC keypairs
   type KeyCache struct {
       keys chan *pqc.MLKEMKeyExchange
   }

   func (c *KeyCache) Pregenerate(count int) {
       for i := 0; i < count; i++ {
           key, _ := pqc.NewMLKEM768KeyExchange()
           c.keys <- key
       }
   }
   ```

3. **Batch Operations**:
   - Batch signature verifications when possible
   - Amortize computational overhead across multiple connections

### 6.2 Network Optimizations

1. **Certificate Compression**:
   ```go
   import "github.com/andybalholm/brotli"

   func compressCertificate(cert []byte) []byte {
       var buf bytes.Buffer
       w := brotli.NewWriterLevel(&buf, brotli.BestCompression)
       w.Write(cert)
       w.Close()
       return buf.Bytes()
   }
   ```

2. **Packet Pacing**:
   - Spread large certificate transmissions across multiple packets
   - Avoid triggering network congestion

3. **Connection Pooling**:
   - Reuse connections to avoid repeated handshakes
   - Especially important with PQC overhead

## 7. Deployment and Migration

### 7.1 Rollout Strategy

**Stage 1: Development and Testing (Months 1-3)**
- Implement hybrid mode support
- Comprehensive testing on testnet
- Performance benchmarking

**Stage 2: Limited Production Pilot (Months 4-6)**
- Deploy to select non-critical services
- Monitor performance and compatibility
- Collect real-world metrics

**Stage 3: Gradual Rollout (Months 7-12)**
- Expand to more services
- Maintain classical fallback
- Monitor for issues

**Stage 4: Default PQC (Months 12+)**
- Enable PQC by default
- Maintain classical support for backward compatibility
- Plan for PQC-only mode

### 7.2 Monitoring and Metrics

**Key Metrics to Track**:

1. **Handshake Performance**:
   - Time to complete handshake (RTT)
   - Number of round trips required
   - Packet loss rate during handshake

2. **Resource Utilization**:
   - CPU usage for crypto operations
   - Memory consumption
   - Bandwidth usage

3. **Compatibility**:
   - Connection success rate
   - Fallback to classical crypto rate
   - Client/server version distribution

**Example Metrics Collection**:
```go
type PQCMetrics struct {
    HandshakeDuration    prometheus.Histogram
    CertificateSize      prometheus.Histogram
    KEMOperationTime     prometheus.Histogram
    SignatureVerifyTime  prometheus.Histogram
    HandshakeFailures    prometheus.Counter
}
```

### 7.3 Backward Compatibility

Maintain compatibility with non-PQC clients:

```go
func (cs *cryptoSetup) negotiateCrypto(peerSupport pqc.SupportedAlgorithms) error {
    switch cs.cryptoMode {
    case pqc.CryptoModeClassical:
        // Always use classical
        return nil

    case pqc.CryptoModePQC:
        // Verify peer supports PQC
        if !peerSupportsPQC(peerSupport) {
            return fmt.Errorf("peer does not support PQC")
        }
        return nil

    case pqc.CryptoModeAuto:
        // Negotiate based on mutual support
        return cs.NegotiateCrypto(peerSupport)

    default:
        return fmt.Errorf("unknown crypto mode: %v", cs.cryptoMode)
    }
}

func peerSupportsPQC(support pqc.SupportedAlgorithms) bool {
    for _, kem := range support.KeyExchangeAlgorithms {
        if strings.HasPrefix(kem, "ML-KEM-") {
            return true
        }
    }
    return false
}
```

## 8. Security Considerations

### 8.1 Dual-Support Mode Security

The dual-support approach provides:
- **Clear Security Model**: Either classical or PQC, never hybrid overhead
- **User Choice**: Applications decide based on their threat model
- **Quantum Protection**: PQC mode provides full quantum resistance
- **Backward Compatibility**: Classical mode ensures compatibility with existing deployments
- **Future-Proof**: Easy to add new algorithms without breaking existing code

### 8.2 Mode Selection Guidelines

**Use Classical Mode When**:
- Interoperating with non-PQC-aware systems
- Quantum threats are not immediate concern
- Performance is critical and PQC overhead is unacceptable
- Testing or development environments

**Use PQC Mode When**:
- Protecting long-lived sensitive data
- Quantum threats are a concern
- Compliance requires quantum-resistant crypto
- Both endpoints support PQC

**Use Auto Mode When**:
- Deploying mixed environments
- Want to prefer PQC but maintain compatibility
- Gradual migration strategy

### 8.3 Algorithm Selection Security

**Security Level Mapping**:
| Mode | KEM Level | DSA Level | Classical Equivalent | Quantum Security |
|------|-----------|-----------|---------------------|------------------|
| Classical | N/A | N/A | X25519 + ECDSA | None |
| PQC-512 | 512 | 44 | AES-128 | ~128-bit |
| PQC-768 | 768 | 65 | AES-192 | ~192-bit |
| PQC-1024 | 1024 | 87 | AES-256 | ~256-bit |

### 8.4 Side-Channel Resistance

PQC algorithms have different side-channel profiles:
- Use constant-time implementations (circl library provides these)
- Be aware of timing attacks on lattice operations
- Consider masking techniques for sensitive operations

### 8.5 Algorithm Agility

Design for easy algorithm updates:

```go
type CryptoProvider interface {
    KeyExchange() KeyExchangeAlgorithm
    Signature() SignatureAlgorithm
}

// Easy to swap implementations
func NewPQCProvider(version int) CryptoProvider {
    switch version {
    case 1:
        return &MLKEM768Provider{}
    case 2:
        return &FutureAlgorithmProvider{}
    }
}
```

## 9. Standards and Compliance

### 9.1 Relevant Standards

- **NIST FIPS 203**: ML-KEM Standard
- **NIST FIPS 204**: ML-DSA Standard
- **RFC 9000**: QUIC Protocol
- **RFC 9001**: TLS 1.3 for QUIC
- **RFC 8879**: TLS Certificate Compression
- **IETF draft-ietf-tls-hybrid-design**: Hybrid PQC TLS

### 9.2 Interoperability

Ensure compatibility with other QUIC implementations:
- Follow IETF working group recommendations
- Participate in interop testing events
- Support standard algorithm identifiers
- Document deviations from standards

## 10. Future Considerations

### 10.1 Algorithm Evolution

Monitor NIST's ongoing PQC standardization:
- Round 4 algorithms (additional signatures)
- Future algorithm updates
- New security analysis

### 10.2 Hardware Support

As PQC hardware accelerators emerge:
- Design modular crypto interfaces
- Support hardware offload when available
- Benchmark against software implementations

### 10.3 Protocol Evolution

QUIC and TLS will evolve for PQC:
- Follow IETF TLS WG developments
- Implement new extensions as standardized
- Participate in standardization process

## 11. Resources and References

### 11.1 Implementation Libraries

**Production-Ready**:
- **Go Standard Library (1.24+)**: https://pkg.go.dev/crypto/mlkem
  - ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - FIPS 140-3 validated
  - Security audited by Trail of Bits

- **Cloudflare CIRCL**: https://github.com/cloudflare/circl
  - Package docs: https://pkg.go.dev/github.com/cloudflare/circl
  - ML-KEM: https://pkg.go.dev/github.com/cloudflare/circl/kem/mlkem
  - ML-DSA: https://pkg.go.dev/github.com/cloudflare/circl/sign/mldsa
  - SLH-DSA: https://pkg.go.dev/github.com/cloudflare/circl/sign/slhdsa

- **filippo.io/mlkem768**: https://filippo.io/mlkem768
  - Pure-Go ML-KEM-768 implementation
  - Source: https://github.com/FiloSottile/mlkem768

**Research/Experimental**:
- **Open Quantum Safe liboqs**: https://github.com/open-quantum-safe/liboqs
  - Go bindings: https://github.com/open-quantum-safe/liboqs-go
  - 30+ PQC algorithms

**NIST Resources**:
- **NIST PQC Project**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **FIPS 203 (ML-KEM)**: https://csrc.nist.gov/pubs/fips/203/final
- **FIPS 204 (ML-DSA)**: https://csrc.nist.gov/pubs/fips/204/final
- **FIPS 205 (SLH-DSA)**: https://csrc.nist.gov/pubs/fips/205/final

### 11.2 Research Papers

- Kempf, M. et al. (2024). "A Quantum of QUIC: Dissecting Cryptography with Post-Quantum Insights"
- NIST (2024). FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST (2024). FIPS 204: Module-Lattice-Based Digital Signature Standard

### 11.3 Tools and Testing

- **PQC Interop Test Suite**: https://test.openquantumsafe.org
- **TLS Testing**: https://github.com/open-quantum-safe/oqs-provider
- **Performance Benchmarks**: https://bench.cr.yp.to/results-kem.html

## 12. Usage Examples

### 12.1 Basic Usage

**Server with PQC enabled**:
```go
// Create PQC-enabled server
listener, err := quic.ListenAddr("localhost:4433", tlsConfig, &quic.Config{
    CryptoMode:          "pqc",
    PQCKeyExchangeLevel: 768,
    PQCSignatureLevel:   65,
})

conn, err := listener.Accept(context.Background())
// Handle connection...
```

**Client connecting with PQC**:
```go
// Connect with PQC
conn, err := quic.DialAddr("localhost:4433", tlsConfig, &quic.Config{
    CryptoMode:          "pqc",
    PQCKeyExchangeLevel: 768,
    PQCSignatureLevel:   65,
})

// Check negotiated algorithm
state := conn.ConnectionState()
fmt.Printf("Using %s for key exchange\n", state.KeyExchangeAlgorithm)
```

### 12.2 Auto-Negotiation

**Server that supports both modes**:
```go
// Server auto-negotiates based on client capabilities
listener, err := quic.ListenAddr("localhost:4433", tlsConfig, &quic.Config{
    CryptoMode:          "auto", // Prefer PQC, fallback to classical
    PQCKeyExchangeLevel: 768,
    PQCSignatureLevel:   65,
})
```

**Client that prefers PQC but falls back**:
```go
conn, err := quic.DialAddr("localhost:4433", tlsConfig, &quic.Config{
    CryptoMode: "auto",
})

// Check what was negotiated
state := conn.ConnectionState()
if strings.HasPrefix(state.KeyExchangeAlgorithm, "ML-KEM-") {
    fmt.Println("Connected with PQC!")
} else {
    fmt.Println("Fell back to classical crypto")
}
```

### 12.3 Migration Strategy Example

**Phase 1: Deploy auto-mode servers**:
```go
// Existing servers update config to support both
config := &quic.Config{
    CryptoMode: "auto", // Accept both classical and PQC clients
}
```

**Phase 2: Update clients to prefer PQC**:
```go
// New client deployments use PQC when available
config := &quic.Config{
    CryptoMode: "auto", // Will use PQC if server supports it
}
```

**Phase 3: Enforce PQC for sensitive applications**:
```go
// High-security applications require PQC
config := &quic.Config{
    CryptoMode:          "pqc", // Only accept PQC connections
    PQCKeyExchangeLevel: 1024,  // Higher security level
    PQCSignatureLevel:   87,
}
```

## 13. Conclusion

Migrating quic-go to support post-quantum cryptography is essential for long-term security. The recommended dual-support approach provides:

1. **Independent Implementations**: Keep classical and PQC separate for clarity and maintainability
2. **User Choice**: Let applications decide based on their security requirements
3. **Easy Migration**: Simple configuration change to enable PQC
4. **Backward Compatibility**: Classical mode remains default, ensuring existing deployments work
5. **Future-Ready**: Clean architecture makes it easy to add new algorithms

**Implementation Strategy**:
1. Add PQC support alongside existing classical crypto
2. Use configuration flags to select mode
3. Implement algorithm negotiation for seamless interoperability
4. Test both modes thoroughly
5. Deploy with classical as default, allow opt-in to PQC
6. Gradually encourage PQC adoption
7. Eventually make PQC default when ecosystem matures

With this approach, quic-go can achieve quantum resistance while maintaining excellent performance and backward compatibility, positioning it as a leading protocol for secure communication in the post-quantum era.

---

**Document Version**: 2.0 (Dual-Support Approach)
**Last Updated**: January 2025
**Authors**: Based on TCC research by Maurício Machado Fernandes Filho
**Status**: Ready for Implementation

**Key Changes in v2.0**:
- Replaced hybrid approach with dual-support (independent classical/PQC)
- Added crypto provider interface for clean abstraction
- Simplified configuration with mode selection
- Added algorithm negotiation for interoperability
- Provided clear migration path and usage examples
