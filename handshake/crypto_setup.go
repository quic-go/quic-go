package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"sync"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
)

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte) (crypto.AEAD, error)

// The CryptoSetup handles all things crypto for the Session
type CryptoSetup struct {
	connID  protocol.ConnectionID
	version protocol.VersionNumber
	scfg    *ServerConfig
	nonce   []byte

	secureAEAD                  crypto.AEAD
	forwardSecureAEAD           crypto.AEAD
	receivedForwardSecurePacket bool

	keyDerivation KeyDerivationFunction

	mutex sync.RWMutex
}

// NewCryptoSetup creates a new CryptoSetup instance
func NewCryptoSetup(connID protocol.ConnectionID, version protocol.VersionNumber, scfg *ServerConfig) *CryptoSetup {
	nonce := make([]byte, 32)
	if _, err := rand.Reader.Read(nonce); err != nil {
		panic(err)
	}
	return &CryptoSetup{
		connID:        connID,
		version:       version,
		scfg:          scfg,
		nonce:         nonce,
		keyDerivation: crypto.DeriveKeysChacha20,
	}
}

// Open a message
func (h *CryptoSetup) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext io.Reader) (*bytes.Reader, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	data, err := ioutil.ReadAll(ciphertext)
	if err != nil {
		return nil, err
	}

	if h.forwardSecureAEAD != nil {
		res, err := h.forwardSecureAEAD.Open(packetNumber, associatedData, bytes.NewReader(data))
		if err == nil {
			h.receivedForwardSecurePacket = true
			return res, nil
		}
		if h.receivedForwardSecurePacket {
			return nil, err
		}
	}
	if h.secureAEAD != nil {
		return h.secureAEAD.Open(packetNumber, associatedData, bytes.NewReader(data))
	}
	return (&crypto.NullAEAD{}).Open(packetNumber, associatedData, bytes.NewReader(data))
}

// Seal a messageTag
func (h *CryptoSetup) Seal(packetNumber protocol.PacketNumber, b *bytes.Buffer, associatedData []byte, plaintext []byte) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.receivedForwardSecurePacket {
		h.forwardSecureAEAD.Seal(packetNumber, b, associatedData, plaintext)
	} else if h.secureAEAD != nil {
		h.secureAEAD.Seal(packetNumber, b, associatedData, plaintext)
	} else {
		(&crypto.NullAEAD{}).Seal(packetNumber, b, associatedData, plaintext)
	}
}

// HandleCryptoMessage handles the crypto handshake and returns the answer
func (h *CryptoSetup) HandleCryptoMessage(data []byte) ([]byte, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	messageTag, cryptoData, err := ParseHandshakeMessage(data)
	if err != nil {
		return nil, err
	}
	if messageTag != TagCHLO {
		return nil, errors.New("Session: expected CHLO")
	}

	if scid, ok := cryptoData[TagSCID]; ok && bytes.Equal(h.scfg.ID, scid) {
		// We have a CHLO with a proper server config ID, do a 0-RTT handshake
		return h.handleCHLO(data, cryptoData)
	}

	// We have an inacholate or non-matching CHLO, we now send a rejection
	return h.handleInchoateCHLO(data)
}

func (h *CryptoSetup) handleInchoateCHLO(data []byte) ([]byte, error) {
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
		TagSNO:  h.nonce,
		TagPROF: proof,
	})
	return serverReply.Bytes(), nil
}

func (h *CryptoSetup) handleCHLO(data []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	// We have a CHLO matching our server config, we can continue with the 0-RTT handshake
	sharedSecret, err := h.scfg.kex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}
	var nonce bytes.Buffer
	nonce.Write(cryptoData[TagNONC])
	nonce.Write(h.nonce)

	h.secureAEAD, err = h.keyDerivation(false, sharedSecret, nonce.Bytes(), h.connID, data, h.scfg.Get(), h.scfg.signer.GetCertUncompressed())
	if err != nil {
		return nil, err
	}
	// TODO: Use new curve
	h.forwardSecureAEAD, err = h.keyDerivation(true, sharedSecret, nonce.Bytes(), h.connID, data, h.scfg.Get(), h.scfg.signer.GetCertUncompressed())
	if err != nil {
		return nil, err
	}

	var reply bytes.Buffer
	WriteHandshakeMessage(&reply, TagSHLO, map[Tag][]byte{
		TagPUBS: h.scfg.kex.PublicKey(),
		TagSNO:  h.nonce,
		TagVER:  protocol.SupportedVersionsAsTags,
		TagICSL: []byte{0x1e, 0x00, 0x00, 0x00}, //30
		TagMSPC: []byte{0x64, 0x00, 0x00, 0x00}, //100
	})
	return reply.Bytes(), nil
}
