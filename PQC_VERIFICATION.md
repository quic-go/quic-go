# Post-Quantum Cryptography Verification Guide

This document shows multiple ways to verify that PQC (Post-Quantum Cryptography) is working correctly in quic-go.

## 1. Automated Tests

### Full Integration Test

Tests all 4 modes with actual QUIC connections:

```bash
go test -v -run TestPQCHandshake
```

**Expected Output:**
```
=== RUN   TestPQCHandshake/PQC_Mode_with_ML-KEM-768
    Key exchange: CurveID(65281) (ID: 0xff01)  ← ML-KEM-768 ✓

=== RUN   TestPQCHandshake/PQC_Mode_with_ML-KEM-1024
    Key exchange: CurveID(65282) (ID: 0xff02)  ← ML-KEM-1024 ✓

=== RUN   TestPQCHandshake/Classical_Mode
    Key exchange: X25519 (ID: 0x001d)         ← Classical ✓

=== RUN   TestPQCHandshake/Auto_Mode
    Key exchange: CurveID(65281) (ID: 0xff01)  ← Prefers PQC ✓
```

### Key Size Verification Test

Verifies actual cryptographic key sizes match PQC specifications:

```bash
go test -v -run TestPQCKeyExchangeVerification
```

**Expected Output:**
```
=== RUN   TestPQCKeyExchangeVerification/ML-KEM-768
    Algorithm: ML-KEM-768
    Security Level: 768-bit
    Client public key size: 1184 bytes  ← NIST FIPS 203 spec ✓
    Server ciphertext size: 1088 bytes  ← NIST FIPS 203 spec ✓
    Shared secret size: 32 bytes
    ✅ Shared secrets match

=== RUN   TestPQCKeyExchangeVerification/ML-KEM-1024
    Algorithm: ML-KEM-1024
    Security Level: 1024-bit
    Client public key size: 1568 bytes ← NIST FIPS 203 spec ✓
    Server ciphertext size: 1568 bytes ← NIST FIPS 203 spec ✓
    Shared secret size: 32 bytes
    ✅ Shared secrets match
```

**What This Proves:**
- ✅ Key sizes match **NIST FIPS 203** (ML-KEM standard)
- ✅ Both sides derive **identical shared secrets**
- ✅ PQC is actually being used (keys are **36-49x larger** than X25519's 32 bytes)

## 2. Live Demo with Example Programs

### Terminal 1: Start PQC Server

```bash
# ML-KEM-768 mode
go run example/pqc_server/main.go pqc 768

# Or ML-KEM-1024 mode
go run example/pqc_server/main.go pqc 1024

# Or classical mode
go run example/pqc_server/main.go classical
```

### Terminal 2: Run PQC Client

```bash
# ML-KEM-768 mode
go run example/pqc_client/main.go pqc 768

# Or ML-KEM-1024 mode
go run example/pqc_client/main.go pqc 1024

# Or classical mode
go run example/pqc_client/main.go classical
```

**Expected Output (Server):**
```
2025/10/16 14:00:00 Starting server with CryptoMode=pqc, SecurityLevel=768
2025/10/16 14:00:00 Server listening on localhost:4242
2025/10/16 14:00:05 Accepted connection from 127.0.0.1:xxxxx
2025/10/16 14:00:05 Received: Hello from pqc mode (security level 768)!
2025/10/16 14:00:05 Sent: Echo: Hello from pqc mode (security level 768)!
```

**Expected Output (Client):**
```
2025/10/16 14:00:05 Connecting with CryptoMode=pqc, SecurityLevel=768
2025/10/16 14:00:05 Connected successfully!
2025/10/16 14:00:05 Sent: Hello from pqc mode (security level 768)!
2025/10/16 14:00:05 Received: Echo: Hello from pqc mode (security level 768)!
```

## 3. Key Differences Between PQC and Classical

| Aspect | Classical (X25519) | ML-KEM-768 | ML-KEM-1024 |
|--------|-------------------|------------|-------------|
| **Curve ID** | `0x001d` (29) | `0xff01` (65281) | `0xff02` (65282) |
| **Public Key Size** | 32 bytes | **1184 bytes** | **1568 bytes** |
| **Ciphertext Size** | 32 bytes | **1088 bytes** | **1568 bytes** |
| **Quantum Safe** | ❌ No | ✅ Yes | ✅ Yes |
| **Security Level** | ~128-bit | ~192-bit | ~256-bit |
| **Standard** | RFC 7748 | NIST FIPS 203 | NIST FIPS 203 |

**Key Observation:** PQC public keys are **36-49x larger** than classical keys, proving different cryptography is in use.

## 4. Code-Level Verification

### Check TLS Connection State

```go
conn, _ := quic.DialAddr(ctx, "localhost:4242", tlsConfig, quicConfig)
state := conn.ConnectionState()

// Check which curve was negotiated
curveID := state.TLS.CurveID
fmt.Printf("Negotiated curve: 0x%04x\n", curveID)

// Expected values:
// 0x001d = X25519 (classical)
// 0xff01 = ML-KEM-768 (PQC)
// 0xff02 = ML-KEM-1024 (PQC)
```

### Verify Configuration

```go
config := &quic.Config{
    CryptoMode:       "pqc",  // "pqc", "classical", or "auto"
    PQCSecurityLevel: 768,    // 768 or 1024
}
```

## 5. What Each Test Verifies

### TestPQCHandshake
- ✅ Full TLS 1.3 handshake completes
- ✅ Correct curve is negotiated
- ✅ Data can be transmitted
- ✅ All 4 modes work correctly

### TestPQCKeyExchangeVerification
- ✅ Key sizes match NIST specifications
- ✅ KEM encapsulation/decapsulation works
- ✅ Both sides derive same shared secret
- ✅ Cryptographic primitives are correct

### Example Programs
- ✅ Real-world usage works
- ✅ Different modes can be selected
- ✅ Client and server interoperate

## 6. Quick Verification Commands

```bash
# Run all tests
go test -v ./... -run PQC

# Just key size verification
go test -v -run TestPQCKeyExchangeVerification

# Just integration test
go test -v -run TestPQCHandshake

# Run example (in 2 terminals)
go run example/pqc_server/main.go pqc 768 &
go run example/pqc_client/main.go pqc 768
```

## 7. Security Guarantees

✅ **Quantum Resistant:** ML-KEM-768 and ML-KEM-1024 are designed to resist attacks from quantum computers
✅ **NIST Approved:** Based on NIST FIPS 203 standard
✅ **Backward Compatible:** Classical mode still available
✅ **Flexible:** Auto mode tries PQC first, falls back if needed

## 8. Troubleshooting

**If you see X25519 instead of ML-KEM:**
- Check `CryptoMode` is set to `"pqc"` or `"auto"`
- Verify both client and server have PQC enabled
- Check logs for any errors during handshake

**If tests fail:**
- Run `go test -v` for detailed output
- Check Go version is 1.24+ (required for `crypto/mlkem`)
- Verify no build errors with `go build ./...`

## Conclusion

The PQC implementation is verified through:
1. ✅ Automated tests showing correct curve negotiation
2. ✅ Key size verification matching NIST specs
3. ✅ Working example programs
4. ✅ Cryptographic correctness (shared secrets match)

**Result:** quic-go successfully uses post-quantum cryptography! 🎉
