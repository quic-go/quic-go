package handshake

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qtls"
)

const (
	// TLS unexpected_message alert
	alertUnexpectedMessage uint8 = 10
	// TLS internal error
	alertInternalError uint8 = 80
)

type messageType uint8

// TLS handshake message types.
const (
	typeClientHello         messageType = 1
	typeServerHello         messageType = 2
	typeNewSessionTicket    messageType = 4
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
	case typeNewSessionTicket:
		return "NewSessionTicket"
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

type cryptoSetup struct {
	tlsConf *qtls.Config
	conn    *qtls.Conn

	messageChan chan []byte

	ourParams  *TransportParameters
	peerParams *TransportParameters
	paramsChan <-chan []byte

	runner handshakeRunner

	alertChan chan uint8
	// handshakeDone is closed as soon as the go routine running qtls.Handshake() returns
	handshakeDone chan struct{}
	// is closed when Close() is called
	closeChan chan struct{}

	zeroRTTParameters      *TransportParameters
	clientHelloWritten     bool
	clientHelloWrittenChan chan *TransportParameters

	receivedWriteKey chan struct{}
	receivedReadKey  chan struct{}
	// WriteRecord does a non-blocking send on this channel.
	// This way, handleMessage can see if qtls tries to write a message.
	// This is necessary:
	// for servers: to see if a HelloRetryRequest should be sent in response to a ClientHello
	// for clients: to see if a ServerHello is a HelloRetryRequest
	writeRecord chan struct{}

	logger utils.Logger

	perspective protocol.Perspective

	mutex sync.Mutex // protects all members below

	readEncLevel  protocol.EncryptionLevel
	writeEncLevel protocol.EncryptionLevel

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialStream io.Writer
	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeStream io.Writer
	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	oneRTTStream  io.Writer
	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ qtls.RecordLayer = &cryptoSetup{}
var _ CryptoSetup = &cryptoSetup{}

// NewCryptoSetupClient creates a new crypto setup for the client
func NewCryptoSetupClient(
	initialStream io.Writer,
	handshakeStream io.Writer,
	oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	remoteAddr net.Addr,
	tp *TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *congestion.RTTStats,
	logger utils.Logger,
) (CryptoSetup, <-chan *TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	cs, clientHelloWritten := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		tlsConf,
		enable0RTT,
		rttStats,
		logger,
		protocol.PerspectiveClient,
	)
	cs.conn = qtls.Client(newConn(remoteAddr), cs.tlsConf)
	return cs, clientHelloWritten
}

// NewCryptoSetupServer creates a new crypto setup for the server
func NewCryptoSetupServer(
	initialStream io.Writer,
	handshakeStream io.Writer,
	oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	remoteAddr net.Addr,
	tp *TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *congestion.RTTStats,
	logger utils.Logger,
) CryptoSetup {
	cs, _ := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		tlsConf,
		enable0RTT,
		rttStats,
		logger,
		protocol.PerspectiveServer,
	)
	cs.conn = qtls.Server(newConn(remoteAddr), cs.tlsConf)
	return cs
}

func newCryptoSetup(
	initialStream io.Writer,
	handshakeStream io.Writer,
	oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *congestion.RTTStats,
	logger utils.Logger,
	perspective protocol.Perspective,
) (*cryptoSetup, <-chan *TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective)
	extHandler := newExtensionHandler(tp.Marshal(), perspective)
	cs := &cryptoSetup{
		initialStream:          initialStream,
		initialSealer:          initialSealer,
		initialOpener:          initialOpener,
		handshakeStream:        handshakeStream,
		oneRTTStream:           oneRTTStream,
		aead:                   newUpdatableAEAD(rttStats, logger),
		readEncLevel:           protocol.EncryptionInitial,
		writeEncLevel:          protocol.EncryptionInitial,
		runner:                 runner,
		ourParams:              tp,
		paramsChan:             extHandler.TransportParameters(),
		logger:                 logger,
		perspective:            perspective,
		handshakeDone:          make(chan struct{}),
		alertChan:              make(chan uint8),
		clientHelloWrittenChan: make(chan *TransportParameters, 1),
		messageChan:            make(chan []byte, 100),
		receivedReadKey:        make(chan struct{}),
		receivedWriteKey:       make(chan struct{}),
		writeRecord:            make(chan struct{}, 1),
		closeChan:              make(chan struct{}),
	}
	qtlsConf := tlsConfigToQtlsConfig(tlsConf, cs, extHandler, cs.marshalPeerParamsForSessionState, cs.handlePeerParamsFromSessionState, cs.accept0RTT, cs.rejected0RTT, enable0RTT)
	cs.tlsConf = qtlsConf
	return cs, cs.clientHelloWrittenChan
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) {
	h.aead.SetLargestAcked(pn)
}

func (h *cryptoSetup) RunHandshake() {
	// Handle errors that might occur when HandleData() is called.
	handshakeComplete := make(chan struct{})
	handshakeErrChan := make(chan error, 1)
	go func() {
		defer close(h.handshakeDone)
		if err := h.conn.Handshake(); err != nil {
			handshakeErrChan <- err
			return
		}
		close(handshakeComplete)
	}()

	select {
	case <-handshakeComplete: // return when the handshake is done
		h.runner.OnHandshakeComplete()
		// send a session ticket
		if h.perspective == protocol.PerspectiveServer {
			h.maybeSendSessionTicket()
		}
	case <-h.closeChan:
		close(h.messageChan)
		// wait until the Handshake() go routine has returned
		<-h.handshakeDone
	case alert := <-h.alertChan:
		handshakeErr := <-handshakeErrChan
		h.onError(alert, handshakeErr.Error())
	}
}

func (h *cryptoSetup) onError(alert uint8, message string) {
	h.runner.OnError(qerr.CryptoError(alert, message))
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
// It must only be called once.
func (h *cryptoSetup) Close() error {
	close(h.closeChan)
	// wait until qtls.Handshake() actually returned
	<-h.handshakeDone
	return nil
}

// handleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
// It returns if it is done with messages on the same encryption level.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) bool /* stream finished */ {
	msgType := messageType(data[0])
	h.logger.Debugf("Received %s message (%d bytes, encryption level: %s)", msgType, len(data), encLevel)
	if err := h.checkEncryptionLevel(msgType, encLevel); err != nil {
		h.onError(alertUnexpectedMessage, err.Error())
		return false
	}
	h.messageChan <- data
	if encLevel == protocol.Encryption1RTT {
		h.handlePostHandshakeMessage()
	}
	var strFinished bool
	switch h.perspective {
	case protocol.PerspectiveClient:
		strFinished = h.handleMessageForClient(msgType)
	case protocol.PerspectiveServer:
		strFinished = h.handleMessageForServer(msgType)
	default:
		panic("")
	}
	if strFinished {
		h.logger.Debugf("Done with encryption level %s.", encLevel)
	}
	return strFinished
}

func (h *cryptoSetup) checkEncryptionLevel(msgType messageType, encLevel protocol.EncryptionLevel) error {
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
	case typeNewSessionTicket:
		expected = protocol.Encryption1RTT
	default:
		return fmt.Errorf("unexpected handshake message: %d", msgType)
	}
	if encLevel != expected {
		return fmt.Errorf("expected handshake message %s to have encryption level %s, has %s", msgType, expected, encLevel)
	}
	return nil
}

func (h *cryptoSetup) handleMessageForServer(msgType messageType) bool {
	switch msgType {
	case typeClientHello:
		select {
		case <-h.writeRecord:
			// If qtls sends a HelloRetryRequest, it will only write the record.
			// If it accepts the ClientHello, it will first read the transport parameters.
			h.logger.Debugf("Sending HelloRetryRequest")
			return false
		case data := <-h.paramsChan:
			h.handleTransportParameters(data)
		case <-h.handshakeDone:
			return false
		}
		// get the handshake read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeDone:
			return false
		}
		// get the handshake write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeDone:
			return false
		}
		// get the 1-RTT write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeDone:
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
		case <-h.handshakeDone:
			return false
		}
		return true
	default:
		// unexpected message
		return false
	}
}

func (h *cryptoSetup) handleMessageForClient(msgType messageType) bool {
	switch msgType {
	case typeServerHello:
		// get the handshake write key
		select {
		case <-h.writeRecord:
			// If qtls writes in response to a ServerHello, this means that this ServerHello
			// is a HelloRetryRequest.
			// Otherwise, we'd just wait for the Certificate message.
			h.logger.Debugf("ServerHello is a HelloRetryRequest")
			return false
		case <-h.receivedWriteKey:
		case <-h.handshakeDone:
			return false
		}
		// get the handshake read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeDone:
			return false
		}
		return true
	case typeEncryptedExtensions:
		select {
		case data := <-h.paramsChan:
			h.handleTransportParameters(data)
		case <-h.handshakeDone:
			return false
		}
		return false
	case typeCertificateRequest, typeCertificate, typeCertificateVerify:
		// nothing to do
		return false
	case typeFinished:
		// get the 1-RTT read key
		select {
		case <-h.receivedReadKey:
		case <-h.handshakeDone:
			return false
		}
		// get the handshake write key
		select {
		case <-h.receivedWriteKey:
		case <-h.handshakeDone:
			return false
		}
		return true
	default:
		return false
	}
}

func (h *cryptoSetup) handleTransportParameters(data []byte) {
	var tp TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		h.runner.OnError(qerr.Error(qerr.TransportParameterError, err.Error()))
	}
	h.peerParams = &tp
	h.runner.OnReceivedParams(h.peerParams)
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalPeerParamsForSessionState() []byte {
	return h.peerParams.MarshalForSessionTicket()
}

func (h *cryptoSetup) handlePeerParamsFromSessionState(data []byte) {
	tp, err := h.handlePeerParamsFromSessionStateImpl(data)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.zeroRTTParameters = tp
}

func (h *cryptoSetup) handlePeerParamsFromSessionStateImpl(data []byte) (*TransportParameters, error) {
	r := bytes.NewReader(data)
	version, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if version != transportParameterMarshalingVersion {
		return nil, fmt.Errorf("unknown transport parameter marshaling version: %d", version)
	}
	var tp TransportParameters
	if err := tp.Unmarshal(data[len(data)-r.Len():], protocol.PerspectiveServer); err != nil {
		return nil, err
	}
	return &tp, nil
}

// only valid for the server
func (h *cryptoSetup) maybeSendSessionTicket() {
	var appData []byte
	// Save transport parameters to the session ticket if we're allowing 0-RTT.
	if h.tlsConf.MaxEarlyData > 0 {
		appData = h.ourParams.MarshalForSessionTicket()
	}
	ticket, err := h.conn.GetSessionTicket(appData)
	if err != nil {
		h.onError(alertInternalError, err.Error())
		return
	}
	if ticket != nil {
		h.oneRTTStream.Write(ticket)
	}
}

// accept0RTT is called for the server when receiving the client's session ticket.
// It decides whether to accept 0-RTT.
func (h *cryptoSetup) accept0RTT(sessionTicketData []byte) bool {
	var tp TransportParameters
	if err := tp.UnmarshalFromSessionTicket(sessionTicketData); err != nil {
		h.logger.Debugf("Unmarshaling transport parameters from session ticket failed: %s", err.Error())
		return false
	}
	valid := h.ourParams.ValidFor0RTT(&tp)
	if valid {
		h.logger.Debugf("Accepting 0-RTT.")
	} else {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
	}
	return valid
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *cryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	h.mutex.Lock()
	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil
	h.mutex.Unlock()

	if had0RTTKeys {
		h.runner.DropKeys(protocol.Encryption0RTT)
	}
}

func (h *cryptoSetup) handlePostHandshakeMessage() {
	// make sure the handshake has already completed
	<-h.handshakeDone

	done := make(chan struct{})
	defer close(done)

	// h.alertChan is an unbuffered channel.
	// If an error occurs during conn.HandlePostHandshakeMessage,
	// it will be sent on this channel.
	// Read it from a go-routine so that HandlePostHandshakeMessage doesn't deadlock.
	alertChan := make(chan uint8, 1)
	go func() {
		select {
		case alert := <-h.alertChan:
			alertChan <- alert
		case <-done:
		}
	}()

	if err := h.conn.HandlePostHandshakeMessage(); err != nil {
		h.onError(<-alertChan, err.Error())
	}
}

// ReadHandshakeMessage is called by TLS.
// It blocks until a new handshake message is available.
func (h *cryptoSetup) ReadHandshakeMessage() ([]byte, error) {
	msg, ok := <-h.messageChan
	if !ok {
		return nil, errors.New("error while handling the handshake message")
	}
	return msg, nil
}

func (h *cryptoSetup) SetReadKey(encLevel qtls.EncryptionLevel, suite *qtls.CipherSuiteTLS13, trafficSecret []byte) {
	h.mutex.Lock()
	switch encLevel {
	case qtls.Encryption0RTT:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret),
			newHeaderProtector(suite, trafficSecret, true),
		)
		h.mutex.Unlock()
		h.logger.Debugf("Installed 0-RTT Read keys (using %s)", cipherSuiteName(suite.ID))
		return
	case qtls.EncryptionHandshake:
		h.readEncLevel = protocol.EncryptionHandshake
		h.handshakeOpener = newHandshakeOpener(
			createAEAD(suite, trafficSecret),
			newHeaderProtector(suite, trafficSecret, true),
			h.dropInitialKeys,
			h.perspective,
		)
		h.logger.Debugf("Installed Handshake Read keys (using %s)", cipherSuiteName(suite.ID))
	case qtls.EncryptionApplication:
		h.readEncLevel = protocol.Encryption1RTT
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		h.logger.Debugf("Installed 1-RTT Read keys (using %s)", cipherSuiteName(suite.ID))
	default:
		panic("unexpected read encryption level")
	}
	h.mutex.Unlock()
	h.receivedReadKey <- struct{}{}
}

func (h *cryptoSetup) SetWriteKey(encLevel qtls.EncryptionLevel, suite *qtls.CipherSuiteTLS13, trafficSecret []byte) {
	h.mutex.Lock()
	switch encLevel {
	case qtls.Encryption0RTT:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret),
			newHeaderProtector(suite, trafficSecret, true),
		)
		h.mutex.Unlock()
		h.logger.Debugf("Installed 0-RTT Write keys (using %s)", cipherSuiteName(suite.ID))
		return
	case qtls.EncryptionHandshake:
		h.writeEncLevel = protocol.EncryptionHandshake
		h.handshakeSealer = newHandshakeSealer(
			createAEAD(suite, trafficSecret),
			newHeaderProtector(suite, trafficSecret, true),
			h.dropInitialKeys,
			h.perspective,
		)
		h.logger.Debugf("Installed Handshake Write keys (using %s)", cipherSuiteName(suite.ID))
	case qtls.EncryptionApplication:
		h.writeEncLevel = protocol.Encryption1RTT
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		h.logger.Debugf("Installed 1-RTT Write keys (using %s)", cipherSuiteName(suite.ID))
		if h.zeroRTTSealer != nil {
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
		}
	default:
		panic("unexpected write encryption level")
	}
	h.mutex.Unlock()
	h.receivedWriteKey <- struct{}{}
}

// WriteRecord is called when TLS writes data
func (h *cryptoSetup) WriteRecord(p []byte) (int, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	switch h.writeEncLevel {
	case protocol.EncryptionInitial:
		// assume that the first WriteRecord call contains the ClientHello
		n, err := h.initialStream.Write(p)
		if !h.clientHelloWritten && h.perspective == protocol.PerspectiveClient {
			h.clientHelloWritten = true
			if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
				h.logger.Debugf("Doing 0-RTT.")
				h.clientHelloWrittenChan <- h.zeroRTTParameters
			} else {
				h.logger.Debugf("Not doing 0-RTT. Has Sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
				h.clientHelloWrittenChan <- nil
			}
		} else {
			// We need additional signaling to properly detect HelloRetryRequests.
			// For servers: when the ServerHello is written.
			// For clients: when a reply is sent in response to a ServerHello.
			h.writeRecord <- struct{}{}
		}
		return n, err
	case protocol.EncryptionHandshake:
		return h.handshakeStream.Write(p)
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", h.writeEncLevel))
	}
}

func (h *cryptoSetup) SendAlert(alert uint8) {
	h.alertChan <- alert
}

// used a callback in the handshakeSealer and handshakeOpener
func (h *cryptoSetup) dropInitialKeys() {
	h.mutex.Lock()
	h.initialOpener = nil
	h.initialSealer = nil
	h.mutex.Unlock()
	h.runner.DropKeys(protocol.EncryptionInitial)
	h.logger.Debugf("Dropping Initial keys.")
}

func (h *cryptoSetup) DropHandshakeKeys() {
	var dropped bool
	h.mutex.Lock()
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	h.mutex.Unlock()
	if dropped {
		h.runner.DropKeys(protocol.EncryptionHandshake)
		h.logger.Debugf("Dropping Handshake keys.")
	}
}

func (h *cryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *cryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTSealer == nil {
		return nil, errors.New("CryptoSetup: 0-RTT sealer not available")
	}
	return h.zeroRTTSealer, nil
}

func (h *cryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *cryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *cryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *cryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *cryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() ConnectionState {
	return h.conn.ConnectionState()
}
