// +build !go1.14

package handshake

import (
	"crypto/tls"

	"github.com/marten-seemann/qtls"
)

func cipherSuiteName(id uint16) string {
	switch id {
	case qtls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case qtls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case qtls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	default:
		return "unknown cipher suite"
	}
}

func toTLSClientHelloInfo(c *qtls.ClientHelloInfo) *tls.ClientHelloInfo { return c }
