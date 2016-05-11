package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte) (crypto.AEAD, error)

// KeyExchangeFunction is used to make a new KEX
type KeyExchangeFunction func() crypto.KeyExchange

// The CryptoSetup handles all things crypto for the Session
type CryptoSetup struct {
	connID  protocol.ConnectionID
	version protocol.VersionNumber
	scfg    *ServerConfig
	nonce   []byte

	secureAEAD                  crypto.AEAD
	forwardSecureAEAD           crypto.AEAD
	receivedForwardSecurePacket bool
	receivedSecurePacket        bool

	keyDerivation KeyDerivationFunction
	keyExchange   KeyExchangeFunction

	cryptoStream utils.Stream

	connectionParametersManager *ConnectionParametersManager

	mutex sync.RWMutex
}

var _ crypto.AEAD = &CryptoSetup{}

// NewCryptoSetup creates a new CryptoSetup instance
func NewCryptoSetup(connID protocol.ConnectionID, version protocol.VersionNumber, scfg *ServerConfig, cryptoStream utils.Stream, connectionParametersManager *ConnectionParametersManager) *CryptoSetup {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return &CryptoSetup{
		connID:                      connID,
		version:                     version,
		scfg:                        scfg,
		nonce:                       nonce,
		keyDerivation:               crypto.DeriveKeysChacha20,
		keyExchange:                 crypto.NewCurve25519KEX,
		cryptoStream:                cryptoStream,
		connectionParametersManager: connectionParametersManager,
	}
}

// HandleCryptoStream reads and writes messages on the crypto stream
func (h *CryptoSetup) HandleCryptoStream() error {
	for {
		cachingReader := utils.NewCachingReader(h.cryptoStream)
		messageTag, cryptoData, err := ParseHandshakeMessage(cachingReader)
		if err != nil {
			return err
		}
		if messageTag != TagCHLO {
			return errors.New("CryptoSetup: expected CHLO")
		}
		chloData := cachingReader.Get()

		utils.Infof("Got crypto message:\n%s", printHandshakeMessage(cryptoData))

		sniSlice, ok := cryptoData[TagSNI]
		if !ok {
			return errors.New("expected SNI in handshake map")
		}
		sni := string(sniSlice)
		if sni == "" {
			return errors.New("expected SNI in handshake map")
		}

		var reply []byte
		if !h.isInchoateCHLO(cryptoData) {
			// We have a CHLO with a proper server config ID, do a 0-RTT handshake
			reply, err = h.handleCHLO(sni, chloData, cryptoData)
			if err != nil {
				return err
			}
			_, err = h.cryptoStream.Write(reply)
			if err != nil {
				return err
			}
			return nil
		}

		// We have an inchoate or non-matching CHLO, we now send a rejection
		reply, err = h.handleInchoateCHLO(sni, chloData, cryptoData)
		if err != nil {
			return err
		}
		_, err = h.cryptoStream.Write(reply)
		if err != nil {
			return err
		}
	}
}

// Open a message
func (h *CryptoSetup) Open(packetNumber protocol.PacketNumber, associatedData []byte, ciphertext []byte) ([]byte, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.forwardSecureAEAD != nil {
		res, err := h.forwardSecureAEAD.Open(packetNumber, associatedData, ciphertext)
		if err == nil {
			h.receivedForwardSecurePacket = true
			return res, nil
		}
		if h.receivedForwardSecurePacket {
			return nil, err
		}
	}
	if h.secureAEAD != nil {
		res, err := h.secureAEAD.Open(packetNumber, associatedData, ciphertext)
		if err == nil {
			h.receivedSecurePacket = true
			return res, nil
		}
		if h.receivedSecurePacket {
			return nil, err
		}
	}
	return (&crypto.NullAEAD{}).Open(packetNumber, associatedData, ciphertext)
}

// Seal a messageTag
func (h *CryptoSetup) Seal(packetNumber protocol.PacketNumber, associatedData []byte, plaintext []byte) []byte {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.receivedForwardSecurePacket {
		return h.forwardSecureAEAD.Seal(packetNumber, associatedData, plaintext)
	} else if h.secureAEAD != nil {
		return h.secureAEAD.Seal(packetNumber, associatedData, plaintext)
	} else {
		return (&crypto.NullAEAD{}).Seal(packetNumber, associatedData, plaintext)
	}
}

func (h *CryptoSetup) isInchoateCHLO(cryptoData map[Tag][]byte) bool {
	scid, ok := cryptoData[TagSCID]
	if !ok || !bytes.Equal(h.scfg.ID, scid) {
		return true
	}
	sno, ok := cryptoData[TagSNO]
	if !ok || !bytes.Equal(h.nonce, sno) {
		return true
	}
	return false
}

func (h *CryptoSetup) handleInchoateCHLO(sni string, data []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	var chloOrNil []byte
	if h.version > protocol.VersionNumber(30) {
		chloOrNil = data
	}

	proof, err := h.scfg.Sign(sni, chloOrNil)
	if err != nil {
		return nil, err
	}

	commonSetHashes := cryptoData[TagCCS]
	cachedCertsHashes := cryptoData[TagCCRT]

	certCompressed, err := h.scfg.GetCertsCompressed(sni, commonSetHashes, cachedCertsHashes)
	if err != nil {
		return nil, err
	}

	var serverReply bytes.Buffer
	WriteHandshakeMessage(&serverReply, TagREJ, map[Tag][]byte{
		TagSCFG: h.scfg.Get(),
		TagCERT: certCompressed,
		TagSNO:  h.nonce,
		TagPROF: proof,
	})
	return serverReply.Bytes(), nil
}

func (h *CryptoSetup) handleCHLO(sni string, data []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	// We have a CHLO matching our server config, we can continue with the 0-RTT handshake
	sharedSecret, err := h.scfg.kex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}
	var nonce bytes.Buffer
	nonce.Write(cryptoData[TagNONC])
	nonce.Write(h.nonce)

	h.mutex.Lock()
	defer h.mutex.Unlock()

	certUncompressed, err := h.scfg.signer.GetLeafCert(sni)
	if err != nil {
		return nil, err
	}

	h.secureAEAD, err = h.keyDerivation(false, sharedSecret, nonce.Bytes(), h.connID, data, h.scfg.Get(), certUncompressed)
	if err != nil {
		return nil, err
	}

	// Generate a new curve instance to derive the forward secure key
	ephermalKex := h.keyExchange()
	ephermalSharedSecret, err := ephermalKex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}
	h.forwardSecureAEAD, err = h.keyDerivation(true, ephermalSharedSecret, nonce.Bytes(), h.connID, data, h.scfg.Get(), certUncompressed)
	if err != nil {
		return nil, err
	}

	err = h.connectionParametersManager.SetFromMap(cryptoData)
	if err != nil {
		return nil, err
	}

	replyMap := h.connectionParametersManager.GetSHLOMap()
	// add crypto parameters
	replyMap[TagPUBS] = ephermalKex.PublicKey()
	replyMap[TagSNO] = h.nonce
	replyMap[TagVER] = protocol.SupportedVersionsAsTags

	var reply bytes.Buffer
	WriteHandshakeMessage(&reply, TagSHLO, replyMap)

	return reply.Bytes(), nil
}
