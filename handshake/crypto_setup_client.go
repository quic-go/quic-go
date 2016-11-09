package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type cryptoSetupClient struct {
	connID  protocol.ConnectionID
	version protocol.VersionNumber

	cryptoStream utils.Stream

	serverConfig *serverConfigClient
	diversificationNonce []byte
}

var _ crypto.AEAD = &cryptoSetupClient{}
var _ CryptoSetup = &cryptoSetupClient{}

var (
	errNoObitForClientNonce             = errors.New("No OBIT for client nonce available")
	errConflictingDiversificationNonces = errors.New("Received two different diversification nonces")
)

// NewCryptoSetupClient creates a new CryptoSetup instance for a client
func NewCryptoSetupClient(
	connID protocol.ConnectionID,
	version protocol.VersionNumber,
	cryptoStream utils.Stream,
) (CryptoSetup, error) {
	return &cryptoSetupClient{
		connID:       connID,
		version:      version,
		cryptoStream: cryptoStream,
	}, nil
}

func (h *cryptoSetupClient) HandleCryptoStream() error {
	err := h.sendInchoateCHLO()
	if err != nil {
		return err
	}

	for {
		var shloData bytes.Buffer
		messageTag, cryptoData, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &shloData))
		if err != nil {
			return qerr.HandshakeFailed
		}

		if messageTag == TagSHLO {
			utils.Debugf("Got SHLO:\n%s", printHandshakeMessage(cryptoData))
		} else if messageTag == TagREJ {
			utils.Debugf("Got REJ:\n%s", printHandshakeMessage(cryptoData))
			if scfg, ok := cryptoData[TagSCFG]; ok {
				h.serverConfig, err = parseServerConfig(scfg)
				if err != nil {
					return err
				}
			}
		} else {
			return qerr.InvalidCryptoMessageType
		}
	}
}

func (h *cryptoSetupClient) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	return (&crypto.NullAEAD{}).Open(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupClient) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	return (&crypto.NullAEAD{}).Seal(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupClient) DiversificationNonce() []byte {
	panic("not needed for cryptoSetupClient")
}

func (h *cryptoSetupClient) SetDiversificationNonce(data []byte) error {
	if len(h.diversificationNonce) == 0 {
		h.diversificationNonce = data
		return nil
	}
	if !bytes.Equal(h.diversificationNonce, data) {
		return errConflictingDiversificationNonces
	}
	return nil
}

func (h *cryptoSetupClient) LockForSealing() {

}

func (h *cryptoSetupClient) UnlockForSealing() {

}

func (h *cryptoSetupClient) HandshakeComplete() bool {
	return false
}

func (h *cryptoSetupClient) getInchoateCHLOValues() map[Tag][]byte {
	tags := make(map[Tag][]byte)
	tags[TagSNI] = []byte("quic.clemente.io") // TODO: use real SNI here
	tags[TagPDMD] = []byte("X509")
	tags[TagPAD] = bytes.Repeat([]byte("0"), protocol.ClientHelloMinimumSize)

	versionTag := make([]byte, 4, 4)
	binary.LittleEndian.PutUint32(versionTag, protocol.VersionNumberToTag(h.version))
	tags[TagVER] = versionTag

	return tags
}

func (h *cryptoSetupClient) sendInchoateCHLO() error {
	b := &bytes.Buffer{}

	tags := h.getInchoateCHLOValues()
	WriteHandshakeMessage(b, TagCHLO, tags)

	_, err := h.cryptoStream.Write(b.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (h *cryptoSetupClient) generateClientNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	binary.BigEndian.PutUint32(nonce, uint32(time.Now().Unix()))

	if len(h.serverConfig.obit) != 8 {
		return nil, errNoObitForClientNonce
	}

	copy(nonce[4:12], h.serverConfig.obit)

	_, err := rand.Read(nonce[12:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
