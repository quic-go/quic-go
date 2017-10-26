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
type KeyDerivationFunction func(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error)

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	keyDerivation KeyDerivationFunction

	tls  mintTLS
	conn *fakeConn

	nullAEAD crypto.AEAD
	aead     crypto.AEAD

	aeadChanged chan<- protocol.EncryptionLevel
}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
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
	conn := &fakeConn{stream: cryptoStream, pers: protocol.PerspectiveServer}
	mintConn := mint.Server(conn, mintConf)
	eh := newExtensionHandlerServer(params, paramsChan, supportedVersions, version)
	if err := mintConn.SetExtensionHandler(eh); err != nil {
		return nil, err
	}

	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		perspective:   protocol.PerspectiveServer,
		tls:           &mintController{mintConn},
		conn:          conn,
		nullAEAD:      nullAEAD,
		keyDerivation: crypto.DeriveAESKeys,
		aeadChanged:   aeadChanged,
	}, nil
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	hostname string,
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
	conn := &fakeConn{stream: cryptoStream, pers: protocol.PerspectiveClient}
	mintConn := mint.Client(conn, mintConf)
	eh := newExtensionHandlerClient(params, paramsChan, initialVersion, supportedVersions, version)
	if err := mintConn.SetExtensionHandler(eh); err != nil {
		return nil, err
	}

	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		conn:          conn,
		perspective:   protocol.PerspectiveClient,
		tls:           &mintController{mintConn},
		nullAEAD:      nullAEAD,
		keyDerivation: crypto.DeriveAESKeys,
		aeadChanged:   aeadChanged,
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
handshakeLoop:
	for {
		switch alert := h.tls.Handshake(); alert {
		case mint.AlertNoAlert: // handshake complete
			break handshakeLoop
		case mint.AlertWouldBlock:
			h.conn.UnblockRead()
		default:
			return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
		}
	}

	aead, err := h.keyDerivation(h.tls, h.perspective)
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
