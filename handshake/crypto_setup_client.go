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

	stk                  []byte
	sno                  []byte
	nonc                 []byte
	diversificationNonce []byte
	lastSentCHLO         []byte
	certManager          *crypto.CertManager
}

var _ crypto.AEAD = &cryptoSetupClient{}
var _ CryptoSetup = &cryptoSetupClient{}

var (
	errNoObitForClientNonce             = errors.New("CryptoSetup BUG: No OBIT for client nonce available")
	errClientNonceAlreadyExists         = errors.New("CryptoSetup BUG: A client nonce was already generated")
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
		certManager:  &crypto.CertManager{},
	}, nil
}

func (h *cryptoSetupClient) HandleCryptoStream() error {
	for {
		err := h.sendCHLO()
		if err != nil {
			return err
		}

		var shloData bytes.Buffer

		messageTag, cryptoData, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &shloData))
		if err != nil {
			return qerr.HandshakeFailed
		}

		if messageTag != TagSHLO && messageTag != TagREJ {
			return qerr.InvalidCryptoMessageType
		}

		if messageTag == TagSHLO {
			utils.Debugf("Got SHLO:\n%s", printHandshakeMessage(cryptoData))
			panic("SHLOs not yet implemented.")
		}

		if messageTag == TagREJ {
			err = h.handleREJMessage(cryptoData)
			if err != nil {
				return err
			}
		}
	}
}

func (h *cryptoSetupClient) handleREJMessage(cryptoData map[Tag][]byte) error {
	utils.Debugf("Got REJ:\n%s", printHandshakeMessage(cryptoData))

	var err error

	if stk, ok := cryptoData[TagSTK]; ok {
		h.stk = stk
	}

	if sno, ok := cryptoData[TagSNO]; ok {
		h.sno = sno
	}

	// TODO: what happens if the server sends a different server config in two packets?
	if scfg, ok := cryptoData[TagSCFG]; ok {
		h.serverConfig, err = parseServerConfig(scfg)
		if err != nil {
			return err
		}

		// now that we have a server config, we can use its OBIT value to generate a client nonce
		if len(h.nonc) == 0 {
			err = h.generateClientNonce()
			if err != nil {
				return err
			}
		}
	}

	if crt, ok := cryptoData[TagCERT]; ok {
		err := h.certManager.SetData(crt)
		if err != nil {
			return err
		}
	}

	return nil
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

func (h *cryptoSetupClient) sendCHLO() error {
	b := &bytes.Buffer{}

	tags := h.getTags()
	WriteHandshakeMessage(b, TagCHLO, tags)

	_, err := h.cryptoStream.Write(b.Bytes())
	if err != nil {
		return err
	}

	h.lastSentCHLO = b.Bytes()

	return nil
}

func (h *cryptoSetupClient) getTags() map[Tag][]byte {
	tags := make(map[Tag][]byte)
	tags[TagSNI] = []byte("quic.clemente.io") // TODO: use real SNI here
	tags[TagPDMD] = []byte("X509")
	tags[TagPAD] = bytes.Repeat([]byte("0"), protocol.ClientHelloMinimumSize)

	versionTag := make([]byte, 4, 4)
	binary.LittleEndian.PutUint32(versionTag, protocol.VersionNumberToTag(h.version))
	tags[TagVER] = versionTag

	if len(h.stk) > 0 {
		tags[TagSTK] = h.stk
	}

	if len(h.sno) > 0 {
		tags[TagSNO] = h.sno
	}

	if h.serverConfig != nil {
		tags[TagSCID] = h.serverConfig.ID
	}

	return tags
}

func (h *cryptoSetupClient) generateClientNonce() error {
	if len(h.nonc) > 0 {
		return errClientNonceAlreadyExists
	}

	nonc := make([]byte, 32)
	binary.BigEndian.PutUint32(nonc, uint32(time.Now().Unix()))

	if len(h.serverConfig.obit) != 8 {
		return errNoObitForClientNonce
	}

	copy(nonc[4:12], h.serverConfig.obit)

	_, err := rand.Read(nonc[12:])
	if err != nil {
		return err
	}

	h.nonc = nonc
	return nil
}
