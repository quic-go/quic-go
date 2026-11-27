package handshake

import (
	"crypto"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/tls"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const aeadNonceLength = 12

type cipherSuite struct {
	ID     uint16
	Hash   crypto.Hash
	KeyLen int
	AEAD   func(key, nonceMask []byte) cipher.AEAD
}

func (s cipherSuite) IVLen() int { return aeadNonceLength }

// IntegrityLimit returns the number of packets that may fail authentication
// before RFC 9001, Section 6.6 requires closing the connection.
func (s cipherSuite) IntegrityLimit() uint64 {
	switch s.ID {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		return protocol.InvalidPacketLimitAES
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return protocol.InvalidPacketLimitChaCha
	default:
		panic(fmt.Sprintf("unknown cipher suite %d", s.ID))
	}
}

func getCipherSuite(id uint16) cipherSuite {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		// The usual convention is to only panic on fips140.Enforced (and not on fips140.Enabled),
		// but this function panics in the default case anyway, so we might as well panic here.
		if fips140.Enabled() {
			panic("tls: TLS_CHACHA20_POLY1305_SHA256 is not allowed in FIPS 140-3 mode")
		}
		return cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, AEAD: aeadAESGCMTLS13}
	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}
