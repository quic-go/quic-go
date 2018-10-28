package handshake

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qtls"
)

type messageType uint8

// TLS handshake message types.
const (
	typeClientHello         messageType = 1
	typeServerHello         messageType = 2
	typeEncryptedExtensions messageType = 8
	typeCertificate         messageType = 11
	typeCertificateRequest  messageType = 13
	typeCertificateVerify   messageType = 15
	typeFinished            messageType = 20
)

func (m messageType) String() string {
	switch m {
	case typeClientHello:
		return "ClientHello"
	case typeServerHello:
		return "ServerHello"
	case typeEncryptedExtensions:
		return "EncryptedExtensions"
	case typeCertificate:
		return "Certificate"
	case typeCertificateRequest:
		return "CertificateRequest"
	case typeCertificateVerify:
		return "CertificateVerify"
	case typeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("unknown message type: %d", m)
	}
}

type cryptoSetupTLS struct {
	tlsConf *qtls.Config

	messageChan chan []byte

	readEncLevel  protocol.EncryptionLevel
	writeEncLevel protocol.EncryptionLevel

	handleParamsCallback func(*TransportParameters)

	// There are two ways that an error can occur during the handshake:
	// 1. as a return value from qtls.Handshake()
	// 2. when new data is passed to the crypto setup via HandleData()
	// handshakeErrChan is closed when qtls.Handshake() errors
	handshakeErrChan chan struct{}
	// HandleData() sends errors on the messageErrChan
	messageErrChan chan error
	// handshakeComplete is closed when the handshake completes
	handshakeComplete chan<- struct{}
	// transport parameters are sent on the receivedTransportParams, as soon as they are received
	receivedTransportParams <-chan TransportParameters
	// is closed when Close() is called
	closeChan chan struct{}

	clientHelloWritten     bool
	clientHelloWrittenChan chan struct{}

	initialStream io.Writer
	initialAEAD   crypto.AEAD

	handshakeStream io.Writer
	handshakeOpener Opener
	handshakeSealer Sealer

	opener Opener
	sealer Sealer
	// TODO: add a 1-RTT stream (used for session tickets)

	receivedWriteKey chan struct{}
	receivedReadKey  chan struct{}

	logger utils.Logger

	perspective protocol.Perspective
}

var _ qtls.RecordLayer = &cryptoSetupTLS{}
var _ CryptoSetupTLS = &cryptoSetupTLS{}

type versionInfo struct {
	initialVersion    protocol.VersionNumber
	supportedVersions []protocol.VersionNumber
	currentVersion    protocol.VersionNumber
}

// NewCryptoSetupTLSClient creates a new TLS crypto setup for the client
func NewCryptoSetupTLSClient(
	initialStream io.Writer,
	handshakeStream io.Writer,
	connID protocol.ConnectionID,
	params *TransportParameters,
	handleParams func(*TransportParameters),
	handshakeComplete chan<- struct{},
	tlsConf *tls.Config,
	initialVersion protocol.VersionNumber,
	supportedVersions []protocol.VersionNumber,
	currentVersion protocol.VersionNumber,
	logger utils.Logger,
	perspective protocol.Perspective,
) (CryptoSetupTLS, <-chan struct{} /* ClientHello written */, error) {
	return newCryptoSetupTLS(
		initialStream,
		handshakeStream,
		connID,
		params,
		handleParams,
		handshakeComplete,
		tlsConf,
		versionInfo{
			currentVersion:    currentVersion,
			initialVersion:    initialVersion,
			supportedVersions: supportedVersions,
		},
		logger,
		perspective,
	)
}

// NewCryptoSetupTLSServer creates a new TLS crypto setup for the server
func NewCryptoSetupTLSServer(
	initialStream io.Writer,
	handshakeStream io.Writer,
	connID protocol.ConnectionID,
	params *TransportParameters,
	handleParams func(*TransportParameters),
	handshakeComplete chan<- struct{},
	tlsConf *tls.Config,
	supportedVersions []protocol.VersionNumber,
	currentVersion protocol.VersionNumber,
	logger utils.Logger,
	perspective protocol.Perspective,
) (CryptoSetupTLS, error) {
	cs, _, err := newCryptoSetupTLS(
		initialStream,
		handshakeStream,
		connID,
		params,
		handleParams,
		handshakeComplete,
		tlsConf,
		versionInfo{
			currentVersion:    currentVersion,
			supportedVersions: supportedVersions,
		},
		logger,
		perspective,
	)
	return cs, err
}

func newCryptoSetupTLS(
	initialStream io.Writer,
	handshakeStream io.Writer,
	connID protocol.ConnectionID,
	params *TransportParameters,
	handleParams func(*TransportParameters),
	handshakeComplete chan<- struct{},
	tlsConf *tls.Config,
	versionInfo versionInfo,
	logger utils.Logger,
	perspective protocol.Perspective,
) (CryptoSetupTLS, <-chan struct{} /* ClientHello written */, error) {
	initialAEAD, err := crypto.NewNullAEAD(perspective, connID, protocol.VersionTLS)
	if err != nil {
		return nil, nil, err
	}
	cs := &cryptoSetupTLS{
		initialStream:          initialStream,
		initialAEAD:            initialAEAD,
		handshakeStream:        handshakeStream,
		readEncLevel:           protocol.EncryptionInitial,
		writeEncLevel:          protocol.EncryptionInitial,
		handleParamsCallback:   handleParams,
		handshakeComplete:      handshakeComplete,
		logger:                 logger,
		perspective:            perspective,
		handshakeErrChan:       make(chan struct{}),
		messageErrChan:         make(chan error, 1),
		clientHelloWrittenChan: make(chan struct{}),
		messageChan:            make(chan []byte, 100),
		receivedReadKey:        make(chan struct{}),
		receivedWriteKey:       make(chan struct{}),
		closeChan:              make(chan struct{}),
	}
	var extHandler tlsExtensionHandler
	switch perspective {
	case protocol.PerspectiveClient:
		extHandler, cs.receivedTransportParams = newExtensionHandlerClient(
			params,
			versionInfo.initialVersion,
			versionInfo.supportedVersions,
			versionInfo.currentVersion,
			logger,
		)
	case protocol.PerspectiveServer:
		extHandler, cs.receivedTransportParams = newExtensionHandlerServer(
			params,
			versionInfo.supportedVersions,
			versionInfo.currentVersion,
			logger,
		)
	}
	qtlsConf := tlsConfigToQtlsConfig(tlsConf)
	qtlsConf.AlternativeRecordLayer = cs
	qtlsConf.GetExtensions = extHandler.GetExtensions
	qtlsConf.ReceivedExtensions = extHandler.ReceivedExtensions
	cs.tlsConf = qtlsConf
	return cs, cs.clientHelloWrittenChan, nil
}

func (h *cryptoSetupTLS) RunHandshake() error {
	var conn *qtls.Conn
	switch h.perspective {
	case protocol.PerspectiveClient:
		conn = qtls.Client(nil, h.tlsConf)
	case protocol.PerspectiveServer:
		conn = qtls.Server(nil, h.tlsConf)
	}
	// Handle errors that might occur when HandleData() is called.
	handshakeErrChan := make(chan error, 1)
	handshakeComplete := make(chan struct{})
	go func() {
		if err := conn.Handshake(); err != nil {
			handshakeErrChan <- err
			return
		}
		close(handshakeComplete)
	}()

	select {
	case <-h.closeChan:
		close(h.messageChan)
		// wait until the Handshake() go routine has returned
		<-handshakeErrChan
		return errors.New("Handshake aborted")
	case <-handshakeComplete: // return when the handshake is done
		close(h.handshakeComplete)
		return nil
	case err := <-handshakeErrChan:
		// if handleMessageFor{server,client} are waiting for some qtls action, make them return
		close(h.handshakeErrChan)
		return err
	case err := <-h.messageErrChan:
		// If the handshake errored because of an error that occurred during HandleData(),
		// that error message will be more useful than the error message generated by Handshake().
		// Close the message chan that qtls is receiving messages from.
		// This will make qtls.Handshake() return.
		// Thereby the go routine running qtls.Handshake() will return.
		close(h.messageChan)
		return err
	}
}

func (h *cryptoSetupTLS) Close() error {
	close(h.closeChan)
	return nil
}

// handleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
// It returns if it is done with messages on the same encryption level.
func (h *cryptoSetupTLS) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) bool /* stream finished */ {
	msgType := messageType(data[0])
	h.logger.Debugf("Received %s message (%d bytes, encryption level: %s)", msgType, len(data), encLevel)
	if err := h.checkEncryptionLevel(msgType, encLevel); err != nil {
		h.messageErrChan <- err
		return false
	}
	h.messageChan <- data
	switch h.perspective {
	case protocol.PerspectiveClient:
		return h.handleMessageForClient(msgType)
	case protocol.PerspectiveServer:
		return h.handleMessageForServer(msgType)
	default:
		panic("")
	}
}

func (h *cryptoSetupTLS) checkEncryptionLevel(msgType messageType, encLevel protocol.EncryptionLevel) error {
	var expected protocol.EncryptionLevel
	switch msgType {
	case typeClientHello,
		typeServerHello:
		expected = protocol.EncryptionInitial
	case typeEncryptedExtensions,
		typeCertificate,
		typeCertificateRequest,
		typeCertificateVerify,
		typeFinished:
		expected = protocol.EncryptionHandshake
	default:
		return fmt.Errorf("unexpected handshake message: %d", msgType)
	}
	if encLevel != expected {
		return fmt.Errorf("expected handshake message %s to have encryption level %s, has %s", msgType, expected, encLevel)
	}
	return nil
}

func (h *cryptoSetupTLS) handleMessageForServer(msgType messageType) bool {
	switch msgType {
	case typeClientHello:
		select {
		case params := <-h.receivedTransportParams:
			h.handleParamsCallback(&params)
		case <-h.handshakeErrChan:
			return false
		}
		// get the handshake write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeErrChan:
			return false
		}
		// get the 1-RTT write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeErrChan:
			return false
		}
		// get the handshake read key
		// TODO: check that the initial stream doesn't have any more data
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeErrChan:
			return false
		}
		return true
	case typeCertificate, typeCertificateVerify:
		// nothing to do
		return false
	case typeFinished:
		// get the 1-RTT read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeErrChan:
			return false
		}
		return true
	default:
		panic("unexpected handshake message")
	}
}

func (h *cryptoSetupTLS) handleMessageForClient(msgType messageType) bool {
	switch msgType {
	case typeServerHello:
		// get the handshake read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeErrChan:
			return false
		}
		return true
	case typeEncryptedExtensions:
		select {
		case params := <-h.receivedTransportParams:
			h.handleParamsCallback(&params)
		case <-h.handshakeErrChan:
			return false
		}
		return false
	case typeCertificateRequest, typeCertificate, typeCertificateVerify:
		// nothing to do
		return false
	case typeFinished:
		// get the handshake write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeErrChan:
			return false
		}
		// While the order of these two is not defined by the TLS spec,
		// we have to do it on the same order as our TLS library does it.
		// get the handshake write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeErrChan:
			return false
		}
		// get the 1-RTT read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeErrChan:
			return false
		}
		return true
	default:
		panic("unexpected handshake message: ")
	}
}

// ReadHandshakeMessage is called by TLS.
// It blocks until a new handshake message is available.
func (h *cryptoSetupTLS) ReadHandshakeMessage() ([]byte, error) {
	// TODO: add some error handling here (when the session is closed)
	msg, ok := <-h.messageChan
	if !ok {
		return nil, errors.New("error while handling the handshake message")
	}
	return msg, nil
}

func (h *cryptoSetupTLS) SetReadKey(suite *qtls.CipherSuite, trafficSecret []byte) {
	key := crypto.HkdfExpandLabel(suite.Hash(), trafficSecret, "key", suite.KeyLen())
	iv := crypto.HkdfExpandLabel(suite.Hash(), trafficSecret, "iv", suite.IVLen())
	opener := newOpener(suite.AEAD(key, iv), iv)

	switch h.readEncLevel {
	case protocol.EncryptionInitial:
		h.readEncLevel = protocol.EncryptionHandshake
		h.handshakeOpener = opener
		h.logger.Debugf("Installed Handshake Read keys")
	case protocol.EncryptionHandshake:
		h.readEncLevel = protocol.Encryption1RTT
		h.opener = opener
		h.logger.Debugf("Installed 1-RTT Read keys")
	default:
		panic("unexpected read encryption level")
	}
	h.receivedReadKey <- struct{}{}
}

func (h *cryptoSetupTLS) SetWriteKey(suite *qtls.CipherSuite, trafficSecret []byte) {
	key := crypto.HkdfExpandLabel(suite.Hash(), trafficSecret, "key", suite.KeyLen())
	iv := crypto.HkdfExpandLabel(suite.Hash(), trafficSecret, "iv", suite.IVLen())
	sealer := newSealer(suite.AEAD(key, iv), iv)

	switch h.writeEncLevel {
	case protocol.EncryptionInitial:
		h.writeEncLevel = protocol.EncryptionHandshake
		h.handshakeSealer = sealer
		h.logger.Debugf("Installed Handshake Write keys")
	case protocol.EncryptionHandshake:
		h.writeEncLevel = protocol.Encryption1RTT
		h.sealer = sealer
		h.logger.Debugf("Installed 1-RTT Write keys")
	default:
		panic("unexpected write encryption level")
	}
	h.receivedWriteKey <- struct{}{}
}

// WriteRecord is called when TLS writes data
func (h *cryptoSetupTLS) WriteRecord(p []byte) (int, error) {
	switch h.writeEncLevel {
	case protocol.EncryptionInitial:
		// assume that the first WriteRecord call contains the ClientHello
		n, err := h.initialStream.Write(p)
		if !h.clientHelloWritten && h.perspective == protocol.PerspectiveClient {
			h.clientHelloWritten = true
			close(h.clientHelloWrittenChan)
		}
		return n, err
	case protocol.EncryptionHandshake:
		return h.handshakeStream.Write(p)
	default:
		return 0, fmt.Errorf("unexpected write encryption level: %s", h.writeEncLevel)
	}
}

func (h *cryptoSetupTLS) GetSealer() (protocol.EncryptionLevel, Sealer) {
	if h.sealer != nil {
		return protocol.Encryption1RTT, h.sealer
	}
	if h.handshakeSealer != nil {
		return protocol.EncryptionHandshake, h.handshakeSealer
	}
	return protocol.EncryptionInitial, h.initialAEAD
}

func (h *cryptoSetupTLS) GetSealerWithEncryptionLevel(level protocol.EncryptionLevel) (Sealer, error) {
	errNoSealer := fmt.Errorf("CryptoSetup: no sealer with encryption level %s", level.String())

	switch level {
	case protocol.EncryptionInitial:
		return h.initialAEAD, nil
	case protocol.EncryptionHandshake:
		if h.handshakeSealer == nil {
			return nil, errNoSealer
		}
		return h.handshakeSealer, nil
	case protocol.Encryption1RTT:
		if h.sealer == nil {
			return nil, errNoSealer
		}
		return h.sealer, nil
	default:
		return nil, errNoSealer
	}
}

func (h *cryptoSetupTLS) OpenInitial(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	return h.initialAEAD.Open(dst, src, pn, ad)
}

func (h *cryptoSetupTLS) OpenHandshake(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	if h.handshakeOpener == nil {
		return nil, errors.New("no handshake opener")
	}
	return h.handshakeOpener.Open(dst, src, pn, ad)
}

func (h *cryptoSetupTLS) Open1RTT(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error) {
	if h.opener == nil {
		return nil, errors.New("no 1-RTT opener")
	}
	return h.opener.Open(dst, src, pn, ad)
}

func (h *cryptoSetupTLS) ConnectionState() ConnectionState {
	// TODO: return the connection state
	return ConnectionState{}
}
