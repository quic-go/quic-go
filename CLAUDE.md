# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

quic-go is a pure Go implementation of the QUIC protocol (RFC 9000, 9001, 9002) with HTTP/3 support (RFC 9114). This is a large, production-grade networking library with extensive test coverage and strict code quality standards.

## Development Commands

### Testing

```bash
# Run unit tests (excluding integration tests)
rm -rf integrationtests && go test -v -shuffle on ./...

# Run unit tests with coverage
go test -v -shuffle on -cover -coverprofile coverage.txt ./...

# Run unit tests with race detector
go test -v -shuffle on -race ./...

# Run benchmarks
go test -v -run=^$ -benchtime 0.5s -bench=. ./...

# Run integration tests
go test -v -timeout 5m -shuffle=on ./integrationtests/self -version=1
go test -v -timeout 5m -shuffle=on ./integrationtests/self -version=2
go test -v -timeout 30s -shuffle=on ./integrationtests/versionnegotiation
go test -v -timeout 30s -shuffle=on ./integrationtests/tools/...

# Run a specific test
go test -v -run TestName ./path/to/package
```

### Linting and Code Quality

```bash
# Run golangci-lint
golangci-lint run --timeout=3m

# Run code generators (mockgen and other go:generate directives)
.github/workflows/go-generate.sh

# Tidy go.mod
go mod tidy

# Format code (handled by golangci-lint)
# The project uses gofmt, gofumpt, and goimports
```

### Mock Generation

Mocks are generated using `go.uber.org/mock/mockgen`. To regenerate mocks:

```bash
go generate -tags=gomock ./...
```

Mock generation is defined in `mockgen.go` and various other files with `//go:generate` directives.

## Architecture

### Core Components

**Connection Management (`connection.go`)**
- The `connection` type is the central state machine managing QUIC connections
- Handles packet processing, flow control, congestion control, loss detection, and stream multiplexing
- Interactions between connection and streams are managed through interfaces like `streamSender`, `streamControlFrameGetter`

**Packet Processing Pipeline**
- `packet_packer.go`: Assembles frames into packets for transmission
- `packet_unpacker.go`: Parses incoming packets and decrypts them
- `send_queue.go` / `send_conn.go`: Handle packet transmission with support for batching and GSO (Generic Segmentation Offload)
- `framer.go`: Manages frame queuing and prioritization

**Stream Management (`streams_map.go`, `send_stream.go`, `receive_stream.go`)**
- `streamsMap`: Manages the lifecycle of all streams on a connection
- Separate implementations for incoming/outgoing and bidirectional/unidirectional streams
- Flow control is handled per-stream and per-connection

**Transport (`client.go`, `server.go`)**
- Client and server use `Transport` type for managing multiple connections
- Connection multiplexing over a single UDP socket
- Stateless reset and connection migration support

### Internal Packages

**`internal/protocol`**: Core QUIC protocol constants, types, and packet/frame definitions
- Version numbers, packet types, stream IDs, connection IDs
- Central place for protocol-level constants

**`internal/wire`**: Frame and packet serialization/deserialization
- Each frame type has its own file (e.g., `stream_frame.go`, `ack_frame.go`)
- Implements binary encoding/decoding for all QUIC frames

**`internal/ackhandler`**: Loss detection and recovery (RFC 9002)
- Packet acknowledgment tracking
- RTT estimation and smoothing
- Congestion control integration

**`internal/congestion`**: Congestion control algorithms
- NewReno and Cubic implementations
- BBR support

**`internal/flowcontrol`**: Stream and connection-level flow control
- Tracks sent/received bytes and manages window updates
- Auto-tuning for receive windows

**`internal/handshake`**: Cryptographic handshake using TLS 1.3
- Uses `qtls` (a fork of crypto/tls) for QUIC integration
- Handles key derivation and rotation

**`internal/qerr`**: QUIC error codes and error handling

**`internal/utils`**: Various utilities (ring buffers, timers, logging)

**`http3/`**: HTTP/3 implementation (RFC 9114)
- Separate from core QUIC implementation
- HTTP/3-specific frame handling and QPACK integration
- Important: `http3/` should NOT depend on `internal/` packages (enforced by linters)

### Key Design Patterns

1. **Interface-Based Design**: Heavy use of interfaces for testability (see `mockgen.go`)
2. **Packet Buffers**: Reusable buffer pools to minimize allocations (`buffer_pool.go`)
3. **Monotonic Time**: Uses `internal/monotime` for timing that's not affected by system clock changes
4. **Encryption Levels**: Separate handling for Initial, Handshake, and 1-RTT encryption
5. **Path MTU Discovery**: Implements DPLPMTUD (RFC 8899) when platform supports it

## Code Style and Requirements

### Linting Rules (from `.golangci.yml`)

- **Do not use** `math/rand` - use `math/rand/v2` instead
- **Do not use** `crypto/rsa` - use `crypto/ed25519` instead
- **Do not use** Ginkgo/Gomega - use standard Go tests with `testing` package
- Use `go.uber.org/mock` for mock generation
- The codebase has strict depguard rules for import restrictions

### Testing

- All tests use standard Go `testing` package (no Ginkgo)
- Tests should use `-shuffle on` to catch order dependencies
- Integration tests are in `integrationtests/` and should be excluded when running unit tests
- Use `TIMESCALE_FACTOR` environment variable to adjust test timeouts (default: 1, CI uses 10-20)
- Some tests require root privileges (tagged with `//go:build root`)

### Platform-Specific Code

- Platform-specific implementations use build tags (e.g., `_linux.go`, `_darwin.go`, `_windows.go`)
- Socket options and DF bit handling vary by platform (see `sys_conn_*.go` files)
- GSO and ECN support is platform-dependent

## Important Development Notes

- **Go Version**: Supports the latest two Go releases (currently 1.24.x and 1.25.x)
- **Experimental Features**: Some tests use `GOEXPERIMENT=synctest` for Go 1.24
- **Code Generation**: Run `.github/workflows/go-generate.sh` after modifying interfaces that need mocks
- **Vendor Support**: The project should work with `go mod vendor` (tested in CI)

## Debugging

- **qlog Support**: The project implements qlog (QUIC event logging) for debugging
- **Environment Variables**:
  - `QLOGFLAG=-qlog`: Enable qlog output in integration tests
  - `QUIC_GO_DISABLE_GSO=true`: Disable Generic Segmentation Offload
  - `QUIC_GO_DISABLE_ECN=true`: Disable Explicit Congestion Notification
  - `TIMESCALE_FACTOR=N`: Scale test timeouts by factor N

## Common Patterns When Contributing

1. When adding a new frame type:
   - Add to `internal/wire/`
   - Implement `Frame` interface
   - Add serialization tests
   - Update `connection.go` to handle the frame

2. When modifying packet handling:
   - Update `packet_packer.go` or `packet_unpacker.go`
   - Consider encryption level implications
   - Update ack handling if needed

3. When adding configuration options:
   - Add to `Config` struct in `interface.go`
   - Document the option thoroughly
   - Add validation in `config.go`
   - Consider backward compatibility
