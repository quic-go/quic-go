package handshake

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type cryptoSetupClient struct {
	connID  protocol.ConnectionID
	version protocol.VersionNumber

	cryptoStream utils.Stream

	hasServerConfig bool
}

var _ crypto.AEAD = &cryptoSetupClient{}
var _ CryptoSetup = &cryptoSetupClient{}

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
	h.sendInchoateCHLO()

	for {
		var chloData bytes.Buffer
		messageTag, cryptoData, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &chloData))
		_ = cryptoData
		utils.Debugf("Received message on Crypto Stream. MessageTag: %#v", messageTag)
		if err != nil {
			return qerr.HandshakeFailed
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
	return nil
}

func (h *cryptoSetupClient) LockForSealing() {

}

func (h *cryptoSetupClient) UnlockForSealing() {

}

func (h *cryptoSetupClient) HandshakeComplete() bool {
	return false
}

func (h *cryptoSetupClient) sendInchoateCHLO() error {
	b := &bytes.Buffer{}

	tags := make(map[Tag][]byte)
	tags[TagSNI] = []byte("quic.clemente.io") // TODO: use real SNI here
	tags[TagPDMD] = []byte("X509")
	tags[TagPAD] = bytes.Repeat([]byte("0"), 1000)

	WriteHandshakeMessage(b, TagCHLO, tags)

	_, err := h.cryptoStream.Write(b.Bytes())
	if err != nil {
		return err
	}
	return nil
}
