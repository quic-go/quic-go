# PQC Testing Guide

This guide explains how to test the Post-Quantum Cryptography (PQC) implementation in quic-go.

## Overview

The PQC implementation supports three cryptographic modes:
- **classical**: Traditional X25519 ECDH (default, backward compatible)
- **pqc**: Post-Quantum ML-KEM (768 or 1024 bit security levels)
- **auto**: Automatic negotiation between classical and PQC

## Quick Start

### 1. Run Unit Tests

Test the PQC crypto primitives:

```bash
go test -v ./internal/handshake/pqc/
```

### 2. Run Integration Tests

Test all crypto modes with example client/server:

```bash
./test_pqc_modes.sh
```

This script tests:
- Classical mode (X25519)
- PQC mode with ML-KEM-768
- PQC mode with ML-KEM-1024
- Auto negotiation mode

### 3. Manual Testing

#### Start a Server

```bash
# Classical mode
go run example/pqc_server/main.go classical

# PQC mode with ML-KEM-768
go run example/pqc_server/main.go pqc 768

# PQC mode with ML-KEM-1024
go run example/pqc_server/main.go pqc 1024

# Auto mode
go run example/pqc_server/main.go auto
```

#### Connect with a Client

In another terminal:

```bash
# Classical mode
go run example/pqc_client/main.go classical

# PQC mode with ML-KEM-768
go run example/pqc_client/main.go pqc 768

# PQC mode with ML-KEM-1024
go run example/pqc_client/main.go pqc 1024

# Auto mode
go run example/pqc_client/main.go auto
```

## Configuration API

### Basic Usage

```go
import "github.com/quic-go/quic-go"

// Classical mode (default)
config := &quic.Config{
    CryptoMode: "classical",
}

// PQC mode with ML-KEM-768 (recommended)
config := &quic.Config{
    CryptoMode:       "pqc",
    PQCSecurityLevel: 768,
}

// PQC mode with ML-KEM-1024 (high security)
config := &quic.Config{
    CryptoMode:       "pqc",
    PQCSecurityLevel: 1024,
}

// Auto negotiation mode
config := &quic.Config{
    CryptoMode:       "auto",
    PQCSecurityLevel: 768, // preferred level
}
```

### Server Example

```go
package main

import (
    "context"
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

func main() {
    tlsConf := &tls.Config{
        // Your TLS config
    }

    config := &quic.Config{
        CryptoMode:       "pqc",
        PQCSecurityLevel: 768,
    }

    listener, err := quic.ListenAddr("localhost:4242", tlsConf, config)
    if err != nil {
        panic(err)
    }
    defer listener.Close()

    conn, err := listener.Accept(context.Background())
    // Handle connection...
}
```

### Client Example

```go
package main

import (
    "context"
    "crypto/tls"
    "github.com/quic-go/quic-go"
)

func main() {
    tlsConf := &tls.Config{
        // Your TLS config
    }

    config := &quic.Config{
        CryptoMode:       "pqc",
        PQCSecurityLevel: 768,
    }

    conn, err := quic.DialAddr(
        context.Background(),
        "localhost:4242",
        tlsConf,
        config,
    )
    if err != nil {
        panic(err)
    }
    defer conn.CloseWithError(0, "")

    // Use connection...
}
```

## Testing Checklist

### Unit Tests
- [x] Crypto mode validation
- [x] Security level validation
- [x] Classical provider (X25519)
- [x] ML-KEM-768 provider
- [x] ML-KEM-1024 provider
- [x] Provider factory
- [x] Key exchange operations

### Integration Tests
- [ ] Classical mode end-to-end connection
- [ ] PQC ML-KEM-768 end-to-end connection
- [ ] PQC ML-KEM-1024 end-to-end connection
- [ ] Auto mode negotiation
- [ ] Mode mismatch handling
- [ ] Security level mismatch handling

### Performance Tests

Run benchmarks:

```bash
go test -bench=. ./internal/handshake/pqc/
```

Expected relative performance:
- Classical (X25519): Baseline (fastest)
- ML-KEM-768: ~2-3x slower than classical
- ML-KEM-1024: ~3-4x slower than classical

### Interoperability Tests

Test connections between different modes:

```bash
# Server in classical, client in classical ✓
# Server in pqc, client in pqc (same level) ✓
# Server in auto, client in classical ✓
# Server in auto, client in pqc ✓
# Server in classical, client in pqc ✗ (should fail gracefully)
```

## Troubleshooting

### Issue: Connection fails with PQC mode

**Cause**: The current implementation integrates PQC at the configuration level, but the actual TLS handshake still uses Go's standard TLS 1.3, which doesn't support PQC key exchange yet.

**Solution**: This is a proof-of-concept implementation. For production use, you'll need to:
1. Use a TLS library that supports PQC (e.g., BoringSSL, OpenSSL 3.x)
2. Integrate PQC key exchange at the TLS extension level
3. Implement custom TLS cipher suites with PQC algorithms

### Issue: Tests pass but connections don't actually use PQC

**Current Status**: The PQC providers are implemented and tested, but they're not yet integrated into the actual TLS handshake. The current implementation:
- ✓ PQC crypto primitives working
- ✓ Configuration API working
- ✗ TLS handshake integration pending

**Next Steps**: See `PQC_MIGRATION_GUIDE.md` for the full integration plan.

## Performance Considerations

### Key Sizes
- X25519: 32 bytes public key
- ML-KEM-768: 1184 bytes public key
- ML-KEM-1024: 1568 bytes public key

### Handshake Overhead
- X25519: ~100 bytes
- ML-KEM-768: ~2400 bytes (public key + ciphertext)
- ML-KEM-1024: ~3136 bytes (public key + ciphertext)

### Recommendations
- Use ML-KEM-768 for most applications (good security/performance balance)
- Use ML-KEM-1024 only for high-security requirements
- Consider packet fragmentation for initial handshake packets

## Next Steps

1. **Complete TLS Integration**: Integrate PQC providers with actual TLS handshake
2. **Add Hybrid Mode**: Support classical + PQC hybrid for maximum compatibility
3. **Add ML-DSA Signatures**: Implement post-quantum signatures
4. **Performance Optimization**: Optimize key generation and encapsulation
5. **Production Hardening**: Add error handling, logging, and metrics

## References

- [NIST FIPS 203 - ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [PQC Migration Guide](./PQC_MIGRATION_GUIDE.md)
- [Go crypto/mlkem Documentation](https://pkg.go.dev/crypto/mlkem)
