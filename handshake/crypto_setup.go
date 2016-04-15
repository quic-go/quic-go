package handshake

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
)

// The CryptoSetup handles all things crypto for the Session
type CryptoSetup struct {
	connID  protocol.ConnectionID
	version protocol.VersionNumber
	aead    crypto.AEAD
	scfg    *ServerConfig
}

// NewCryptoSetup creates a new CryptoSetup instance
func NewCryptoSetup(connID protocol.ConnectionID, version protocol.VersionNumber, scfg *ServerConfig) *CryptoSetup {
	return &CryptoSetup{
		connID:  connID,
		version: version,
		aead:    &crypto.NullAEAD{},
		scfg:    scfg,
	}
}

// Open a message
func (h *CryptoSetup) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext io.Reader) (*bytes.Reader, error) {
	return h.aead.Open(packetNumber, associatedData, ciphertext)
}

// Seal a messageTag
func (h *CryptoSetup) Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte) {
	h.aead.Seal(packetNumber, b, associatedData, plaintext)
}

// HandleCryptoMessage handles the crypto handshake and returns the answer
func (h *CryptoSetup) HandleCryptoMessage(data []byte) ([]byte, error) {
	messageTag, cryptoData, err := ParseHandshakeMessage(data)
	if err != nil {
		return nil, err
	}
	if messageTag != TagCHLO {
		return nil, errors.New("Session: expected CHLO")
	}

	if _, ok := cryptoData[TagSCID]; ok {
		var sharedSecret []byte
		sharedSecret, err = h.scfg.kex.CalculateSharedKey(cryptoData[TagPUBS])
		if err != nil {
			return nil, err
		}
		h.aead, err = crypto.DeriveKeysChacha20(sharedSecret, cryptoData[TagNONC], h.connID, data, h.scfg.Get(), h.scfg.kd.GetCertUncompressed())
		if err != nil {
			return nil, err
		}
		// TODO: Send SHLO
		return nil, nil
	}

	var chloOrNil []byte
	if h.version > protocol.VersionNumber(30) {
		chloOrNil = data
	}

	proof, err := h.scfg.Sign(chloOrNil)
	if err != nil {
		return nil, err
	}

	var serverReply bytes.Buffer
	WriteHandshakeMessage(&serverReply, TagREJ, map[Tag][]byte{
		TagSCFG: h.scfg.Get(),
		TagCERT: h.scfg.GetCertCompressed(),
		TagPROF: proof,
	})
	return serverReply.Bytes(), nil
}
