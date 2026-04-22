# quic-go-pqc: Architecture Principles and File Structure

**Version:** 1.1
**Last Updated:** 2026-04-22
**Purpose:** Define architecture principles and file organization standards for this repository

---

## 1. Architecture Principles

### 1.1 Core Design Principles

#### **Modularity and Separation of Concerns**
- **Provider Pattern:** All cryptographic implementations must implement the `CryptoProvider` interface
- **Factory-Based Selection:** Runtime configuration determines which crypto provider is instantiated
- **Clear Layer Boundaries:**
  - Crypto providers (`internal/handshake/pqc/`) → Handshake setup (`internal/handshake/`) → Connection layer (`connection.go`, `client.go`, `server.go`)
  - HTTP/3 layer (`http3/`) must NOT depend on QUIC internals (`internal/`)

#### **Backward Compatibility**
- **Classical Fallback:** All PQC features must have classical equivalents (X25519 for key exchange; Ed25519 for signatures in hybrid mode, ECDSA-P256 elsewhere)
- **Mode Switching:** Users can switch between `classical`, `pqc`, `hybrid`, and `auto` modes without code changes
- **Graceful Degradation:** If PQC algorithms unavailable, fall back to classical crypto
- **Hybrid Mode:** Composite signatures combine Ed25519 (classical) + ML-DSA (post-quantum) so certificates remain verifiable even if one scheme is broken

#### **Interface-Based Design**
- Heavy use of interfaces for testability and modularity
- Mock generation using `go.uber.org/mock/mockgen` (see `mockgen.go`)
- All external dependencies should be abstracted behind interfaces

#### **Performance Awareness**
- **Buffer Pooling:** Use `buffer_pool.go` for reusable packet buffers (minimize allocations)
- **Zero-Copy Where Possible:** Avoid unnecessary byte slice copies
- **Monotonic Time:** Use `internal/monotime` for timing (immune to system clock adjustments)
- **Platform-Specific Optimizations:** Leverage GSO (Generic Segmentation Offload), ECN (Explicit Congestion Notification) when available

#### **Security-First Approach**
- **Constant-Time Operations:** Cryptographic operations must resist timing attacks
- **Cryptographic Validation:** All crypto implementations validated against Wycheproof test vectors
- **No External Crypto Dependencies in Core:** Only `github.com/cloudflare/circl` for PQC, standard library for classical
- **Minimal Trust Surface:** Crypto code isolated in `internal/handshake/pqc/` and `internal/qtls/`

### 1.2 QUIC Protocol Adherence

This repository implements:
- **QUIC Core:** RFC 9000 (Protocol), RFC 9001 (TLS), RFC 9002 (Recovery)
- **HTTP/3:** RFC 9114, QPACK (RFC 9204), HTTP Datagrams (RFC 9297)
- **Extensions:** RFC 9221 (Datagrams), RFC 8899 (DPLPMTUD), RFC 9369 (QUIC v2)
- **Experimental:** Stream Resets with Partial Delivery, qlog event logging

**PQC Extensions:**
- Custom TLS 1.3 extensions for ML-KEM key exchange
- Custom X.509 certificate handling for ML-DSA signatures
- Transparent integration (no QUIC frame format changes)

### 1.3 Testing Philosophy

#### **Test Coverage Requirements**
- **Unit Tests:** All new providers must have `_test.go` with >80% coverage
- **Integration Tests:** End-to-end QUIC connections for each crypto mode
- **Conformance Tests:** Wycheproof validation for all PQC algorithms
- **Benchmark Tests:** Performance regression detection

#### **Test Execution**
```bash
# Unit tests only (exclude integration tests)
rm -rf integrationtests && go test -v -shuffle on ./...

# With coverage
go test -v -shuffle on -cover -coverprofile coverage.txt ./...

# With race detector
go test -v -shuffle on -race ./...

# Wycheproof conformance
go test -v -run Wycheproof ./...
```

#### **No Ginkgo/Gomega**
- Use standard `testing` package only (enforced by linters)
- Use `github.com/stretchr/testify` for assertions

### 1.4 Code Quality Standards

#### **Linting Rules** (see `.golangci.yml`)
- **Banned Imports:**
  - ❌ `math/rand` → Use `math/rand/v2` instead
  - ❌ `crypto/rsa` → Use `crypto/ed25519` instead
  - ❌ Ginkgo/Gomega → Use `testing` package
- **Required:** `go.uber.org/mock` for mocks
- **Import Restrictions:** Enforced by `depguard` linter

#### **Code Style**
- **Formatting:** `gofmt`, `gofumpt`, `goimports` (run via `golangci-lint`)
- **Line Length:** Soft limit 120 chars, hard limit 150 chars
- **Error Handling:** Always check errors, use `internal/qerr` for QUIC errors
- **Comments:** Exported functions must have godoc comments

---

## 2. File Structure Conventions

### 2.1 Top-Level Directory Structure

```
quic-go-pqc/
├── *.go                      # Core QUIC implementation (connection, transport, etc.)
├── *_test.go                 # Corresponding unit tests
├── internal/                 # Internal packages (not importable externally)
│   ├── handshake/           # TLS handshake logic
│   │   └── pqc/             # PQC crypto providers
│   ├── qtls/                # Custom TLS 1.3 implementation
│   ├── protocol/            # QUIC protocol constants and types
│   ├── wire/                # Frame/packet serialization
│   ├── ackhandler/          # Loss detection and ACK handling
│   ├── congestion/          # Congestion control algorithms
│   ├── flowcontrol/         # Flow control logic
│   ├── utils/               # Utilities (ring buffers, timers, etc.)
│   └── qerr/                # QUIC error codes
├── http3/                   # HTTP/3 implementation
├── example/                 # Example applications
│   ├── pqc_client/          # PQC client example
│   ├── pqc_server/          # PQC server example
│   └── ...                  # Other examples
├── benchmark/               # Performance benchmarking suite
│   ├── server/              # Benchmark server
│   ├── client/              # Benchmark client
│   ├── runner/              # Test orchestrator
│   └── tamago/              # Bare-metal templates
├── integrationtests/        # Integration tests (excluded from unit tests)
├── fuzzing/                 # Fuzz testing targets
├── qlog/                    # qlog event logging
├── docs/                    # Additional documentation (if needed)
└── *.md                     # Documentation files
```

### 2.2 File Naming Conventions

#### **Core Implementation Files**
- `connection.go` - Main connection state machine
- `client.go` - Client-specific logic
- `server.go` - Server-specific logic
- `transport.go` - Transport-layer multiplexing
- `config.go` - Configuration structures
- `interface.go` - Public API interfaces

#### **Supporting Files**
- `packet_packer.go` - Packet assembly
- `packet_unpacker.go` - Packet parsing
- `framer.go` - Frame management
- `send_queue.go` / `send_conn.go` - Transmission logic
- `receive_stream.go` / `send_stream.go` - Stream implementations
- `streams_map.go` - Stream lifecycle management

#### **Platform-Specific Files**
- `sys_conn_df_linux.go` - Linux-specific DF bit handling
- `sys_conn_df_darwin.go` - macOS-specific DF bit handling
- `sys_conn_df_windows.go` - Windows-specific DF bit handling
- `sys_conn_oob.go` - OOB message handling
- `sys_conn_helper_linux.go` - Linux socket helpers

#### **Test Files**
- `*_test.go` - Unit tests (same package)
- `*_go124_test.go` - Go 1.24+ specific tests
- `mock_*.go` - Generated mocks (via `mockgen.go`)

### 2.3 Internal Package Structure

#### **internal/handshake/pqc/** - PQC Crypto Providers
```
pqc/
├── provider.go             # CryptoProvider interface definition
├── factory.go              # NewCryptoProvider() factory function
├── crypto_mode.go          # CryptoMode type and validation
├── classical.go            # X25519 + ECDSA-P256 provider
├── ml_kem.go               # ML-KEM provider (512 / 768 / 1024 via constructor)
├── ml_dsa.go               # ML-DSA signature provider (44 / 65 / 87)
├── hybrid_provider.go      # Hybrid X25519+ML-KEM key exchange provider
├── hybrid_signer.go        # Hybrid Ed25519+ML-DSA composite signer
├── hybrid_signer_test.go   # Hybrid signer tests
└── pqc_test.go             # Comprehensive unit tests
```

**Naming Convention:**
- One provider per file; parameterize variants via constructor args (see `ml_kem.go`, `ml_dsa.go`)
- Hybrid combinators live in `hybrid_*.go`
- Implement all `CryptoProvider` methods

#### **internal/qtls/** - Custom TLS 1.3 Fork
```
qtls/
├── conn.go                     # TLS connection state machine
├── handshake_client.go         # Client handshake (TLS 1.0-1.2)
├── handshake_client_tls13.go   # Client handshake (TLS 1.3)
├── handshake_server.go         # Server handshake (TLS 1.0-1.2)
├── handshake_server_tls13.go   # Server handshake (TLS 1.3)
├── handshake_messages.go       # TLS message parsing
├── cipher_suites.go            # Cipher suite definitions
├── key_schedule.go             # TLS 1.3 key derivation
├── pqc_key_exchange.go         # PQC key exchange integration
├── pqc_signature.go            # PQC signature integration
├── pqc_x509.go                 # PQC X.509 certificate generation (classical + hybrid)
├── pqc_x509_parse.go           # PQC X.509 certificate parsing
├── pqc_x509_hybrid_test.go     # Hybrid certificate generation/parsing tests
└── quic.go                     # QUIC-specific TLS adaptations
```

**Naming Convention:**
- `pqc_*.go` for PQC-specific extensions
- Match standard library `crypto/tls` names for compatibility

#### **internal/protocol/** - QUIC Protocol Constants
```
protocol/
├── version.go           # QUIC version numbers
├── packet_number.go     # Packet number types
├── stream_id.go         # Stream ID types
├── connection_id.go     # Connection ID types
└── transport_parameters.go  # Transport parameters
```

#### **internal/wire/** - Frame and Packet Serialization
```
wire/
├── frame.go              # Frame interface
├── stream_frame.go       # STREAM frame
├── ack_frame.go          # ACK frame
├── crypto_frame.go       # CRYPTO frame
├── connection_close_frame.go  # CONNECTION_CLOSE frame
└── ...                   # Other frame types
```

**Convention:** One file per frame type

### 2.4 Example Applications

```
example/
├── pqc_client/main.go   # Demonstrates client-side PQC usage
├── pqc_server/main.go   # Demonstrates server-side PQC usage
├── client/main.go       # Basic QUIC client
└── echo/echo.go         # Echo server example
```

**Guidelines:**
- Keep examples simple (<200 lines)
- One `main()` function per directory
- Include comments explaining PQC configuration

### 2.5 Benchmarking Suite

```
benchmark/
├── server/main.go               # QUIC server for benchmarking
├── client/main.go               # QUIC client for benchmarking
├── runner/main.go               # Single-size test orchestrator (CSV output)
├── comprehensive_runner/main.go # Multi-size orchestrator (iterates payload sizes)
├── Makefile                     # Build automation
├── Dockerfile                   # Reproducible test environment
├── generate_chart.py            # Throughput / handshake chart generation
├── generate_size_comparison.py  # Scaling charts across payload sizes (with stddev)
├── generate_table.py            # Comparison tables (PNG + EPS)
├── tamago/                      # Bare-metal templates
│   ├── server/main.go
│   └── client/main.go
└── README.md                    # Benchmark documentation
```

**Generated artifacts (gitignored):**
- `benchmark_table_<size>.{png,eps}` — per-size comparison tables
- `charts_<size>/` — per-size chart outputs
- `comprehensive_results_<size>.csv`, `results_*.csv` — raw CSV data
- `scaling_*.{png,eps}` — cross-size scaling views

**Guidelines:**
- Server/client must support all crypto modes (`-mode classical|pqc|hybrid`)
- Output must be machine-parseable (CSV format)
- Runners orchestrate multiple iterations for statistical significance; stddev is reported in charts

### 2.6 Documentation Files

**Top-Level Documentation:**
- `README.md` - Main project README
- `CLAUDE.md` - Development guidelines for AI-assisted coding
- `LICENSE` - MIT License
- `SECURITY.md` - Security policy

**PQC-Specific Documentation:**
- `PQC_README.md` - Quick start guide
- `PQC_IMPLEMENTATION_COMPLETE.md` - Implementation details
- `PQC_IMPLEMENTATION_SUMMARY.md` - Executive summary
- `PQC_MIGRATION_GUIDE.md` - Migration guide
- `PQC_TESTING_GUIDE.md` - Testing procedures
- `PQC_VERIFICATION.md` - Verification methodology
- `ARCHITECTURE.md` - This document

**Local-Only Documents (gitignored):**
- Analysis, planning, or cleanup reports generated during development are kept local and excluded via `.gitignore` (see that file for the current list).

**Convention:**
- All caps for top-level docs (e.g., `README.md`, `LICENSE`)
- `PQC_` prefix for PQC-related docs
- All Markdown (`.md` extension)

---

## 3. Code Organization Patterns

### 3.1 Adding a New PQC Algorithm

**Steps:**
1. Create `internal/handshake/pqc/<algorithm>_<variant>.go`
2. Define struct implementing `CryptoProvider` interface
3. Implement all interface methods:
   - `GenerateKeyPair() (KeyExchange, error)`
   - `GenerateSigner() (Signer, error)`
   - `Mode() CryptoMode`
   - `KeyExchangeAlgorithm() string`
   - `SignatureAlgorithm() string`
   - `SecurityLevel() int`
4. Update `factory.go` to instantiate new provider
5. Add unit tests in `pqc_test.go`
6. Add Wycheproof tests in `wycheproof_test.go`
7. Update documentation

**Example (follows the pattern of `ml_kem.go` / `ml_dsa.go`):**
```go
// internal/handshake/pqc/<algorithm>.go
package pqc

type <Algorithm>Provider struct {
    variant <VariantEnum> // e.g. ML-KEM-512 / 768 / 1024
}

func New<Algorithm>Provider(variant <VariantEnum>) *<Algorithm>Provider { ... }

func (p *<Algorithm>Provider) GenerateKeyPair() (KeyExchange, error) { ... }

// ... other CryptoProvider methods
```

For classical + PQC combinations, follow `hybrid_provider.go` / `hybrid_signer.go`, which compose an existing classical provider with a PQC provider.

### 3.2 Adding a New QUIC Frame Type

**Steps:**
1. Create `internal/wire/<frame_name>_frame.go`
2. Define struct with frame fields
3. Implement `Frame` interface:
   - `Append([]byte, Version) ([]byte, error)` - Serialization
   - `Parse(*bytes.Reader, Version) error` - Deserialization
   - `Length(Version) protocol.ByteCount` - Frame length
4. Update `connection.go` to handle frame in `handleFrame()`
5. Add serialization tests
6. Update framer if frame requires prioritization

### 3.3 Adding Configuration Options

**Steps:**
1. Add field to `Config` struct in `interface.go`
2. Add validation in `config.go` (if needed)
3. Use config value in relevant code (e.g., `connection.go`, `crypto_setup.go`)
4. Update `config_test.go`
5. Document in godoc comments

**Example:**
```go
// interface.go
type Config struct {
    // ... existing fields

    // CryptoMode specifies cryptographic mode: "classical", "pqc", or "auto"
    CryptoMode string
}
```

---

## 4. Dependency Management

### 4.1 Allowed Dependencies

**Production Dependencies:**
- `github.com/cloudflare/circl` - PQC algorithms (ML-KEM, ML-DSA)
- `github.com/quic-go/qpack` - QPACK compression
- `golang.org/x/crypto` - Extended crypto primitives
- `golang.org/x/net` - Network utilities
- `golang.org/x/sync` - Synchronization primitives
- `golang.org/x/sys` - System calls

**Testing Dependencies:**
- `github.com/stretchr/testify` - Test assertions
- `go.uber.org/mock` - Mock generation

**Tool Dependencies:**
- `github.com/jordanlewis/gcassert` - Escape analysis assertions

### 4.2 Forbidden Dependencies

- ❌ `math/rand` - Use `math/rand/v2` instead
- ❌ `crypto/rsa` - Use `crypto/ed25519` instead
- ❌ Ginkgo/Gomega - Use `testing` package
- ❌ Any GPL-licensed libraries (conflicts with MIT license)

### 4.3 Updating Dependencies

```bash
# Update all dependencies
go get -u ./...

# Update specific dependency
go get -u github.com/cloudflare/circl@latest

# Tidy go.mod
go mod tidy

# Vendor dependencies (tested in CI)
go mod vendor
```

---

## 5. Build and Deployment

### 5.1 Build Tags

**Platform-Specific:**
- `//go:build linux` - Linux-only code
- `//go:build darwin` - macOS-only code
- `//go:build windows` - Windows-only code

**Feature-Specific:**
- `//go:build gomock` - Mock generation (in `mockgen.go`)
- `//go:build root` - Tests requiring root privileges

### 5.2 Code Generation

**Mock Generation:**
```bash
go generate -tags=gomock ./...
```

**Defined in:** `mockgen.go` and various `//go:generate` directives

### 5.3 CI/CD Expectations

**GitHub Actions Workflow (`.github/workflows/`):**
- Unit tests on Linux, macOS, Windows
- Go 1.24 and 1.25 compatibility
- Race detector tests
- Vendor mode tests
- Linting with `golangci-lint`

---

## 6. Contribution Guidelines

### 6.1 Commit Message Format

**Convention:** Conventional Commits
- `feat:` - New features
- `fix:` - Bug fixes
- `test:` - Test additions/modifications
- `docs:` - Documentation changes
- `chore:` - Build/tooling changes
- `refactor:` - Code refactoring

**Examples:**
- `feat(pqc): add ML-KEM-768 provider`
- `test: add Wycheproof conformance tests`
- `fix: handle certificate generation errors`

### 6.2 Pull Request Guidelines

1. **One feature per PR** - Keep PRs focused
2. **Tests required** - All new code must have tests
3. **Documentation** - Update relevant docs
4. **Linting** - Run `golangci-lint run` before submitting
5. **Atomic commits** - Each commit should compile and pass tests

### 6.3 Code Review Checklist

- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Documentation updated
- [ ] Linters pass (`golangci-lint run`)
- [ ] No security vulnerabilities introduced
- [ ] Backward compatibility maintained
- [ ] Performance impact considered

---

## 7. Security Considerations

### 7.1 Cryptographic Code

**Requirements:**
- Constant-time operations (use `crypto/subtle` where appropriate)
- Wycheproof validation for all PQC algorithms
- No key material in logs or error messages
- Secure random number generation (`crypto/rand`)

### 7.2 Memory Safety

**Guidelines:**
- Avoid buffer overflows (use slicing carefully)
- Clear sensitive data after use (`crypto/subtle.ConstantTimeCopy`)
- Use buffer pools for packet buffers
- Avoid retaining references to pooled buffers

### 7.3 Disclosure Policy

See `SECURITY.md` for vulnerability reporting process.

---

## 8. Maintenance and Evolution

### 8.1 Versioning

**Go Module Versioning:**
- Major version in module path (e.g., `github.com/quic-go/quic-go/v2`)
- Semantic versioning (MAJOR.MINOR.PATCH)

### 8.2 Deprecation Process

1. Add deprecation notice in godoc comments
2. Keep deprecated code for 1 major version
3. Provide migration path in documentation
4. Remove in next major version

### 8.3 Long-Term Maintenance

**Upstream Sync:**
- This is a fork of `github.com/quic-go/quic-go`
- Periodically sync upstream changes (use `git merge` or `git cherry-pick`)
- Resolve conflicts carefully (PQC changes in `crypto_setup.go`, `config.go`)

**Standard Updates:**
- Track IETF QUIC working group for new RFCs
- Monitor NIST for PQC standard updates
- Update TLS 1.3 implementation as needed

---

## 9. Performance Optimization Guidelines

### 9.1 Profiling

**CPU Profiling:**
```bash
go test -cpuprofile cpu.prof -bench .
go tool pprof cpu.prof
```

**Memory Profiling:**
```bash
go test -memprofile mem.prof -bench .
go tool pprof mem.prof
```

### 9.2 Escape Analysis

**Use gcassert to prevent heap allocations:**
```go
//gcassert:inline
func criticalPath() { ... }
```

### 9.3 Performance Targets

**Handshake Latency:**
- Classical: <10ms
- PQC: <50ms (certificate generation overhead acceptable for prototype)

**Throughput:**
- Should not degrade compared to classical (crypto is not bottleneck)

**Memory:**
- Connection overhead: <100KB per connection
- Packet buffers: Reuse via `buffer_pool.go`

---

## 10. Summary

### Key Takeaways

1. **Modularity First:** Provider pattern for crypto, clear layer separation
2. **Testing is Mandatory:** Unit tests + Wycheproof + integration tests
3. **Documentation Matters:** Code should be self-documenting + comprehensive docs
4. **Performance Awareness:** Profile, optimize, benchmark
5. **Security Rigor:** Constant-time crypto, Wycheproof validation, no shortcuts
6. **Backward Compatibility:** Always provide classical fallback
7. **Clean Commits:** Atomic, well-documented, conventional format
8. **Lint Everything:** `golangci-lint` catches many issues early

### Questions?

For implementation questions, refer to:
- `CLAUDE.md` - AI-assisted development guidelines
- `PQC_MIGRATION_GUIDE.md` - Detailed implementation examples
- Existing code in `internal/handshake/pqc/` - Reference implementations

---

**Document Maintainers:** Mauricio Machado Fernandes Filho
**Review Cycle:** Quarterly (or when major architecture changes occur)
