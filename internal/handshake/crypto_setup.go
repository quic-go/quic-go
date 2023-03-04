package handshake

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/quicvarint"
)

type quicVersionContextKey struct{}

var QUICVersionContextKey = &quicVersionContextKey{}

const clientSessionStateRevision = 3

type cryptoSetup struct {
	tlsConf *tls.Config
	conn    *tls.QUICConn

	version protocol.VersionNumber

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	runner handshakeRunner

	zeroRTTParameters     *wire.TransportParameters
	zeroRTTParametersChan chan<- *wire.TransportParameters
	allow0RTT             bool

	rttStats *utils.RTTStats

	tracer logging.ConnectionTracer
	logger utils.Logger

	perspective protocol.Perspective

	mutex sync.Mutex // protects all members below

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialStream io.Writer
	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeStream io.Writer
	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT bool

	oneRTTStream  io.Writer
	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &cryptoSetup{}

// NewCryptoSetupClient creates a new crypto setup for the client
func NewCryptoSetupClient(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
) (CryptoSetup, <-chan *wire.TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	cs, clientHelloWritten := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveClient,
		version,
	)

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	if tlsConf.ClientSessionCache != nil {
		origCache := tlsConf.ClientSessionCache
		tlsConf.ClientSessionCache = &clientSessionCache{
			wrapped: origCache,
			getData: cs.marshalDataForSessionState,
			setData: cs.handleDataFromSessionState,
		}
	}
	cs.tlsConf = tlsConf

	cs.conn = tls.QUICClient(&tls.QUICConfig{TLSConfig: cs.tlsConf})
	cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient))

	return cs, clientHelloWritten
}

// NewCryptoSetupServer creates a new crypto setup for the server
func NewCryptoSetupServer(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	tlsConf *tls.Config,
	allow0RTT bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
) CryptoSetup {
	cs, _ := newCryptoSetup(
		initialStream,
		handshakeStream,
		oneRTTStream,
		connID,
		tp,
		runner,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveServer,
		version,
	)
	cs.allow0RTT = allow0RTT

	// TODO: this is a hack to initialize the session ticket keys
	tlsConf.DecryptTicket([]byte("foobar"), tls.ConnectionState{})
	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	// add callbacks to save transport parameters into the session ticket
	origWrapSession := tlsConf.WrapSession
	tlsConf.WrapSession = func(cs tls.ConnectionState, state *tls.SessionState) ([]byte, error) {
		// Add QUIC transport parameters if this is a 0-RTT packet.
		// TODO(#3853): also save the RTT for non-0-RTT tickets
		if state.EarlyData {
			// At this point, crypto/tls has just called the WrapSession callback.
			// state.Extra is guaranteed to be empty.
			state.Extra = (&sessionTicket{
				Parameters: tp,
				RTT:        rttStats.SmoothedRTT(),
			}).Marshal()
		}
		if origWrapSession != nil {
			return origWrapSession(cs, state)
		}
		b, err := tlsConf.EncryptTicket(cs, state)
		return b, err
	}
	origUnwrapSession := tlsConf.UnwrapSession
	// UnwrapSession might be called multiple times, as the client can use multiple session tickets.
	// However, using 0-RTT is only possible with the first session ticket.
	// crypto/tls guarantees that this callback is called in the same order as the session ticket in the ClientHello.
	var unwrapCount int
	tlsConf.UnwrapSession = func(identity []byte, connState tls.ConnectionState) (*tls.SessionState, error) {
		unwrapCount++
		var state *tls.SessionState
		var err error
		if origUnwrapSession != nil {
			state, err = origUnwrapSession(identity, connState)
		} else {
			state, err = tlsConf.DecryptTicket(identity, connState)
		}
		if err != nil || state == nil {
			return nil, err
		}
		if state.EarlyData {
			if unwrapCount == 1 { // first session ticket
				state.EarlyData = cs.accept0RTT(state.Extra)
			} else { // subsequent session ticket, can't be used for 0-RTT
				state.EarlyData = false
			}
		}
		return state, nil
	}

	cs.tlsConf = tlsConf
	cs.conn = tls.QUICServer(&tls.QUICConfig{TLSConfig: cs.tlsConf})

	return cs
}

func newCryptoSetup(
	initialStream, handshakeStream, oneRTTStream io.Writer,
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	runner handshakeRunner,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
) (*cryptoSetup, <-chan *wire.TransportParameters /* ClientHello written. Receive nil for non-0-RTT */) {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if tracer != nil {
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
	zeroRTTParametersChan := make(chan *wire.TransportParameters, 1)
	return &cryptoSetup{
		initialStream:         initialStream,
		initialSealer:         initialSealer,
		initialOpener:         initialOpener,
		handshakeStream:       handshakeStream,
		oneRTTStream:          oneRTTStream,
		aead:                  newUpdatableAEAD(rttStats, tracer, logger, version),
		runner:                runner,
		ourParams:             tp,
		rttStats:              rttStats,
		tracer:                tracer,
		logger:                logger,
		perspective:           perspective,
		zeroRTTParametersChan: zeroRTTParametersChan,
		version:               version,
	}, zeroRTTParametersChan
}

func (h *cryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
}

func (h *cryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

func (h *cryptoSetup) StartHandshake() error {
	err := h.conn.Start(context.WithValue(context.Background(), QUICVersionContextKey, h.version))
	if err != nil {
		return wrapError(err)
	}
	for {
		ev := h.conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if err := h.handleEvent(ev); err != nil {
			return wrapError(err)
		}
	}
	if h.perspective == protocol.PerspectiveClient {
		if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			h.logger.Debugf("Doing 0-RTT.")
			h.zeroRTTParametersChan <- h.zeroRTTParameters
		} else {
			h.logger.Debugf("Not doing 0-RTT. Has sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
			h.zeroRTTParametersChan <- nil
		}
	}
	return nil
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *cryptoSetup) Close() error { return h.conn.Close() }

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
func (h *cryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.handleMessage(data, encLevel); err != nil {
		return wrapError(err)
	}
	return nil
}

func (h *cryptoSetup) handleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.conn.HandleData(encLevel.ToTLSEncryptionLevel(), data); err != nil {
		return err
	}
	for {
		ev := h.conn.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			return nil
		}
		if err := h.handleEvent(ev); err != nil {
			return err
		}
	}
}

func (h *cryptoSetup) handleEvent(ev tls.QUICEvent) error {
	switch ev.Kind {
	case tls.QUICSetReadSecret:
		h.SetReadKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICSetWriteSecret:
		h.SetWriteKey(ev.Level, ev.Suite, ev.Data)
		return nil
	case tls.QUICTransportParameters:
		return h.handleTransportParameters(ev.Data)
	case tls.QUICTransportParametersRequired:
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective))
		return nil
	case tls.QUICRejectedEarlyData:
		h.rejected0RTT()
		return nil
	case tls.QUICWriteData:
		return h.WriteRecord(ev.Level, ev.Data)
	case tls.QUICHandshakeDone:
		h.handshakeComplete()
		return nil
	default:
		return fmt.Errorf("unexpected event: %d", ev.Kind)
	}
}

func (h *cryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.runner.OnReceivedParams(h.peerParams)
	return nil
}

// must be called after receiving the transport parameters
func (h *cryptoSetup) marshalDataForSessionState() []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	b = quicvarint.Append(b, uint64(h.rttStats.SmoothedRTT().Microseconds()))
	return h.peerParams.MarshalForSessionTicket(b)
}

func (h *cryptoSetup) handleDataFromSessionState(data []byte) {
	tp, err := h.handleDataFromSessionStateImpl(data)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.zeroRTTParameters = tp
}

func (h *cryptoSetup) handleDataFromSessionStateImpl(data []byte) (*wire.TransportParameters, error) {
	r := bytes.NewReader(data)
	ver, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if ver != clientSessionStateRevision {
		return nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	rtt, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	h.rttStats.SetInitialRTT(time.Duration(rtt) * time.Microsecond)
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(r); err != nil {
		return nil, err
	}
	return &tp, nil
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *cryptoSetup) GetSessionTicket() ([]byte, error) {
	if h.tlsConf.SessionTicketsDisabled {
		return nil, nil
	}
	if err := h.conn.SendSessionTicket(h.allow0RTT); err != nil {
		return nil, err
	}
	ev := h.conn.NextEvent()
	if ev.Kind != tls.QUICWriteData || ev.Level != tls.QUICEncryptionLevelApplication {
		panic("crypto/tls bug: where's my session ticket?")
	}
	ticket := ev.Data
	if ev := h.conn.NextEvent(); ev.Kind != tls.QUICNoEvent {
		panic("crypto/tls bug: why more than one ticket?")
	}
	return ticket, nil
}

// accept0RTT is called for the server when receiving the client's session ticket.
// It decides whether to accept 0-RTT.
func (h *cryptoSetup) accept0RTT(sessionTicketData []byte) bool {
	var t sessionTicket
	if err := t.Unmarshal(sessionTicketData); err != nil {
		h.logger.Debugf("Unmarshalling transport parameters from session ticket failed: %s", err.Error())
		return false
	}
	valid := h.ourParams.ValidFor0RTT(t.Parameters)
	if !valid {
		h.logger.Debugf("Transport parameters changed. Rejecting 0-RTT.")
		return false
	}
	if !h.allow0RTT {
		h.logger.Debugf("0-RTT not allowed. Rejecting 0-RTT.")
		return false
	}
	h.logger.Debugf("Accepting 0-RTT. Restoring RTT from session ticket: %s", t.RTT)
	h.rttStats.SetInitialRTT(t.RTT)
	return true
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

func (h *cryptoSetup) SetReadKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	encLevel := protocol.FromTLSEncryptionLevel(el)
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	switch encLevel {
	case protocol.Encryption0RTT:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.used0RTT = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case protocol.EncryptionHandshake:
		h.handshakeOpener = newHandshakeOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
			h.dropInitialKeys,
			h.perspective,
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case protocol.Encryption1RTT:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.mutex.Unlock()
	h.runner.OnReceivedReadKeys()
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(encLevel, h.perspective.Opposite())
	}
}

func (h *cryptoSetup) SetWriteKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	encLevel := protocol.FromTLSEncryptionLevel(el)
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	switch encLevel {
	case protocol.Encryption0RTT:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.mutex.Unlock()
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.tracer != nil {
			h.tracer.UpdatedKeyFromTLS(protocol.Encryption0RTT, h.perspective)
		}
		// don't set used0RTT here. 0-RTT might still get rejected.
		return
	case protocol.EncryptionHandshake:
		h.handshakeSealer = newHandshakeSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
			h.dropInitialKeys,
			h.perspective,
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			// Once we receive handshake keys, we know that 0-RTT was not rejected.
			h.used0RTT = true
		}
	case protocol.Encryption1RTT:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.tracer != nil {
				h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	h.mutex.Unlock()
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(encLevel, h.perspective)
	}
}

// WriteRecord is called when TLS writes data
func (h *cryptoSetup) WriteRecord(encLevel tls.QUICEncryptionLevel, p []byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var str io.Writer
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case tls.QUICEncryptionLevelInitial:
		// assume that the first WriteRecord call contains the ClientHello
		str = h.initialStream
	case tls.QUICEncryptionLevelHandshake:
		str = h.handshakeStream
	case tls.QUICEncryptionLevelApplication:
		str = h.oneRTTStream
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
	_, err := str.Write(p)
	return err
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

func (h *cryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.runner.OnHandshakeComplete()
}

func (h *cryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
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
		return nil, ErrKeysDropped
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

	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.tracer != nil {
			h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *cryptoSetup) ConnectionState() ConnectionState {
	return ConnectionState{
		ConnectionState: h.conn.ConnectionState(),
		Used0RTT:        h.used0RTT,
	}
}

func wrapError(err error) error {
	if alertErr := tls.AlertError(0); errors.As(err, &alertErr) && alertErr != 80 {
		return qerr.NewLocalCryptoError(uint8(alertErr), err.Error())
	}
	return &qerr.TransportError{ErrorCode: qerr.InternalError, ErrorMessage: err.Error()}
}
