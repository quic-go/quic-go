package handshake

import (
	"crypto/tls"
	"fmt"
	"io"
	"sync"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(crypto.MintController, protocol.Perspective) (crypto.AEAD, error)

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	keyDerivation KeyDerivationFunction

	conn             *mint.Conn
	extensionHandler mint.AppExtensionHandler

	nullAEAD crypto.AEAD
	aead     crypto.AEAD

	aeadChanged chan<- protocol.EncryptionLevel
}

var newMintController = func(conn *mint.Conn) crypto.MintController {
	return &mintController{conn}
}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	cryptoStream io.ReadWriter,
	tlsConfig *tls.Config,
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	aeadChanged chan<- protocol.EncryptionLevel,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) (CryptoSetup, error) {
	mintConf, err := tlsToMintConfig(tlsConfig, protocol.PerspectiveServer)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		perspective:      protocol.PerspectiveServer,
		conn:             mint.Server(&fakeConn{cryptoStream}, mintConf),
		nullAEAD:         crypto.NewNullAEAD(protocol.PerspectiveServer, version),
		keyDerivation:    crypto.DeriveAESKeys,
		aeadChanged:      aeadChanged,
		extensionHandler: newExtensionHandlerServer(params, paramsChan, supportedVersions, version),
	}, nil
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	hostname string, // only needed for the client
	tlsConfig *tls.Config,
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	aeadChanged chan<- protocol.EncryptionLevel,
	initialVersion protocol.VersionNumber,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) (CryptoSetup, error) {
	mintConf, err := tlsToMintConfig(tlsConfig, protocol.PerspectiveClient)
	if err != nil {
		return nil, err
	}
	mintConf.ServerName = hostname

	return &cryptoSetupTLS{
		perspective:      protocol.PerspectiveClient,
		conn:             mint.Client(&fakeConn{cryptoStream}, mintConf),
		nullAEAD:         crypto.NewNullAEAD(protocol.PerspectiveClient, version),
		keyDerivation:    crypto.DeriveAESKeys,
		aeadChanged:      aeadChanged,
		extensionHandler: newExtensionHandlerClient(params, paramsChan, initialVersion, supportedVersions, version),
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
	if err := h.conn.SetExtensionHandler(h.extensionHandler); err != nil {
		return err
	}
	mc := newMintController(h.conn)

	if alert := mc.Handshake(); alert != mint.AlertNoAlert {
		return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
	}

	aead, err := h.keyDerivation(mc, h.perspective)
	if err != nil {
		return err
	}
	h.mutex.Lock()
	h.aead = aead
	h.mutex.Unlock()

	// signal to the outside world that the handshake completed
	h.aeadChanged <- protocol.EncryptionForwardSecure
	close(h.aeadChanged)
	return nil
}

func (h *cryptoSetupTLS) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		data, err := h.aead.Open(dst, src, packetNumber, associatedData)
		if err != nil {
			return nil, protocol.EncryptionUnspecified, err
		}
		return data, protocol.EncryptionForwardSecure, nil
	}
	data, err := h.nullAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return nil, protocol.EncryptionUnspecified, err
	}
	return data, protocol.EncryptionUnencrypted, nil
}

func (h *cryptoSetupTLS) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		return protocol.EncryptionForwardSecure, h.aead
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	errNoSealer := fmt.Errorf("CryptoSetup: no sealer with encryption level %s", encLevel.String())
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.aead == nil {
			return nil, errNoSealer
		}
		return h.aead, nil
	default:
		return nil, errNoSealer
	}
}

func (h *cryptoSetupTLS) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) DiversificationNonce() []byte {
	panic("diversification nonce not needed for TLS")
}

func (h *cryptoSetupTLS) SetDiversificationNonce([]byte) {
	panic("diversification nonce not needed for TLS")
}
