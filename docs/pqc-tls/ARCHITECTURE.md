# Post-Quantum QUIC — New Architecture (PQC on TLS)

This document describes the **current** structure of the post-quantum QUIC
implementation, which is based on **patching the real Go `crypto/tls`** rather
than embedding a fork of it inside quic-go.

> The previous approach (an embedded `internal/qtls` fork of `crypto/tls` plus
> cloudflare/circl) is preserved on the branch `post-quantum-crypto-draft` and
> the consolidation branch `pqc-tls-module`. It is **superseded** by what is
> described here but kept for history.

## Motivation

Upstream Go (master / Go 1.27) now ships post-quantum cryptography **natively**:

- `crypto/tls`: ML-KEM key exchange (`X25519MLKEM768`, `SecP256r1MLKEM768`,
  `SecP384r1MLKEM1024`, pure `MLKEM1024`) and ML-DSA TLS 1.3 signature schemes
  (`MLDSA44/65/87`).
- `crypto/mlkem`, `crypto/mldsa` (FIPS 203 / FIPS 204) and `crypto/x509` ML-DSA
  certificate support.
- The full QUIC TLS API (`QUICConn`, `QUICErrorEvent`, session events).

So almost everything the old fork hand-built is now native, using **standard
codepoints**. We therefore *adopt* native PQC and add only the two features the
project needs that upstream does not provide, as a **small patch to the Go
toolchain**.

## The two layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ Application (example/pqc_client, example/pqc_server, tests)            │
│   configure PQC purely via *tls.Config                                  │
└───────────────┬────────────────────────────────────────────────────────┘
                │ uses
┌───────────────▼───────────────────────┐     ┌──────────────────────────┐
│ quic-go-pqc  (branch: pqc-native)      │     │ pqctls/  (helper package) │
│   • core = byte-for-byte upstream      │────▶│   • curve IDs             │
│     quic-go (uses stdlib crypto/tls)   │     │   • GenerateMLDSACert      │
│   • NO PQC fields on quic.Config       │     │   • GenerateHybridCert     │
│   • NO internal/qtls, NO circl         │     │   • composite sig schemes  │
└───────────────┬───────────────────────┘     └──────────┬───────────────┘
                │ compiled & run with                      │ imports
┌───────────────▼──────────────────────────────────────────▼───────────┐
│ Patched Go toolchain  (go-pqc, branch: pqc-crypto-tls)                 │
│   src/crypto/tls  + src/crypto/x509                                     │
│   • pure ML-KEM-768  (CurveID 513)                                      │
│   • composite Ed25519+ML-DSA certs + signature schemes                  │
│   • Config.SignatureSchemes opt-in field                                │
│   built natively on crypto/mlkem + crypto/mldsa (no external deps)      │
└────────────────────────────────────────────────────────────────────────┘
```

## What runs where

### A. Patched Go toolchain — `go-pqc` (branch `pqc-crypto-tls`)

A fork of `golang/go` master with a small patch (≈170 lines + one new file):

| Feature | Files |
|---------|-------|
| Pure ML-KEM-768 (`CurveID = 513`) | `src/crypto/tls/common.go`, `key_schedule.go`, `defaults.go`, `defaults_fips140.go` |
| Composite Ed25519+ML-DSA cert type, OIDs, parse/marshal | `src/crypto/x509/composite.go` (new), `x509.go`, `parser.go` |
| Composite TLS 1.3 signature scheme + verify | `src/crypto/tls/common.go`, `auth.go`, `handshake_client.go`, `handshake_client_tls13.go` |
| `Config.SignatureSchemes` opt-in field (advertise + accept) | `src/crypto/tls/common.go` (field + `Clone`), `handshake_client*.go` |

The full diff is captured in [`crypto-tls-pqc.patch`](./crypto-tls-pqc.patch),
which applies onto Go commit `6565f551` (master at clone time). Rebuild with
`cd src && GOTOOLCHAIN=local ./make.bash`.

### B. quic-go-pqc — `pqc-native`

- The **core quic-go is unchanged from upstream** (it already uses the stdlib
  `crypto/tls` QUIC API). `connection.go`, `config.go`, `interface.go`,
  `internal/handshake/crypto_setup.go` are byte-for-byte upstream — confirm with
  `git diff --stat upstream/master`.
- `pqctls/` — the only PQC-specific public surface:
  - curve-ID constants `MLKEM768`, `MLKEM1024`, `X25519MLKEM768`
  - `GenerateMLDSACertificate(level, org, dns, validFor)` (native ML-DSA cert)
  - `GenerateHybridCertificate(level, org, dns, validFor)` (composite cert)
  - composite scheme constants `CompositeEd25519MLDSA44/65/87`
- `example/pqc_client`, `example/pqc_server`, `pqc_test.go`, `pqctls/*_test.go`.

## How to select PQC (all via `tls.Config`)

```go
// Key exchange: pick a curve.
tlsConf.CurvePreferences = []tls.CurveID{pqctls.MLKEM768}      // or MLKEM1024 / X25519MLKEM768

// Authentication: install a PQC certificate.
cert, _ := pqctls.GenerateMLDSACertificate(pqctls.MLDSA65, "org", []string{"localhost"}, 24*time.Hour)
tlsConf.Certificates = []tls.Certificate{cert}

// Composite (experimental) — also advertise the scheme on the client:
cert, _ = pqctls.GenerateHybridCertificate(pqctls.MLDSA65, "org", []string{"localhost"}, 24*time.Hour)
clientTLSConf.SignatureSchemes = []tls.SignatureScheme{pqctls.CompositeEd25519MLDSA65}
```

## Building & testing

Always use the patched toolchain:

```sh
export GOROOT=/path/to/go-pqc
export GOTOOLCHAIN=local
$GOROOT/bin/go build ./...
$GOROOT/bin/go test -run TestPQC .
```

Standard modes (hybrid `X25519MLKEM768`, pure `MLKEM1024`, native single ML-DSA
certs) also build on a stock Go 1.27. Pure ML-KEM-768 and composite certs require
the patched toolchain.

## Verified modes (end-to-end QUIC handshake + echo)

| Mode | Curve | Cert |
|------|-------|------|
| Classical | X25519 (`0x001d`) | ECDSA |
| Pure ML-KEM-768 | `0x0201` (513) | ML-DSA-65 |
| Pure ML-KEM-1024 | `0x0202` (514) | ML-DSA-87 |
| Hybrid KEX | `0x11ec` (X25519MLKEM768) | ML-DSA-65 |
| Composite cert | `0x11ec` | Ed25519+ML-DSA-65 (composite) |

The session-resumption / 0-RTT / error-event handshake tests, which failed under
the old embedded-qtls approach, pass here (modern stdlib TLS).
