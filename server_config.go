package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex crypto.KeyExchange
	kd  *crypto.KeyData
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, kd *crypto.KeyData) *ServerConfig {
	return &ServerConfig{
		kex: kex,
		kd:  kd,
	}
}

// Get the server config binary representation
func (s *ServerConfig) Get() []byte {
	var serverConfig bytes.Buffer
	WriteCryptoMessage(&serverConfig, TagSCFG, map[Tag][]byte{
		TagSCID: []byte{0xC5, 0x1C, 0x73, 0x6B, 0x8F, 0x48, 0x49, 0xAE, 0xB3, 0x00, 0xA2, 0xD4, 0x4B, 0xA0, 0xCF, 0xDF},
		TagKEXS: []byte("C255"),
		TagAEAD: []byte("AESG"),
		TagPUBS: append([]byte{0x20, 0x00, 0x00}, s.kex.PublicKey()...),
		TagOBIT: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
		TagEXPY: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		TagVER:  []byte("Q032"),
	})
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(chlo []byte) ([]byte, error) {
	return s.kd.SignServerProof(chlo, s.Get())
}

// GetCertData returns the certificate data
func (s *ServerConfig) GetCertData() []byte {
	return s.kd.GetCERTdata()
}
