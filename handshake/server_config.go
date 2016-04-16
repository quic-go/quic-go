package handshake

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex    crypto.KeyExchange
	signer crypto.Signer
	ID     []byte
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, signer crypto.Signer) *ServerConfig {
	id := make([]byte, 16)
	_, err := rand.Reader.Read(id)
	if err != nil {
		panic(err)
	}
	return &ServerConfig{
		kex:    kex,
		signer: signer,
		ID:     id,
	}
}

// Get the server config binary representation
func (s *ServerConfig) Get() []byte {
	var serverConfig bytes.Buffer
	WriteHandshakeMessage(&serverConfig, TagSCFG, map[Tag][]byte{
		TagSCID: s.ID,
		TagKEXS: []byte("C255"),
		TagAEAD: []byte("CC20"),
		TagPUBS: append([]byte{0x20, 0x00, 0x00}, s.kex.PublicKey()...),
		TagOBIT: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
		TagEXPY: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		TagVER:  []byte("Q032"),
	})
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(chlo []byte) ([]byte, error) {
	return s.signer.SignServerProof(chlo, s.Get())
}

// GetCertCompressed returns the certificate data
func (s *ServerConfig) GetCertCompressed() []byte {
	return s.signer.GetCertCompressed()
}
