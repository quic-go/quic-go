package quic

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   net.Addr
	publicHeader *PublicHeader
	data         []byte
	rcvTime      time.Time
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
	errSessionAlreadyClosed       = errors.New("cannot close session; it was already closed before")
)

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

type handshakeEvent struct {
	encLevel protocol.EncryptionLevel
	err      error
}

type closeError struct {
	err    error
	remote bool
}

// A Session is a QUIC session
type session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	config       *Config

	conn                 connection
	streamsMap           *streamsMap
	rttStats             *congestion.RTTStats
	sentPacketHandler    ackhandler.SentPacketHandler
	flowControlManager   flowcontrol.FlowControlManager
	cryptoSetup          handshake.CryptoSetup
	connectionParameters handshake.ConnectionParametersManager

	sessionSender   sessionSender
	sessionReceiver sessionReceiver

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	runClosed chan struct{}
	closeOnce sync.Once

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the current encryption level
	// it is closed as soon as the handshake is complete
	aeadChanged       <-chan protocol.EncryptionLevel
	handshakeComplete bool
	// will be closed as soon as the handshake completes, and receive any error that might occur until then
	// it is used to block WaitUntilHandshakeComplete()
	handshakeCompleteChan chan error
	// handshakeChan receives handshake events and is closed as soon the handshake completes
	// the receiving end of this channel is passed to the creator of the session
	// it receives at most 3 handshake events: 2 when the encryption level changes, and one error
	handshakeChan chan<- handshakeEvent

	sessionCreationTime time.Time

	timer           *time.Timer
	currentDeadline time.Time
	timerRead       bool
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	config *Config,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,
	}
	return s.setup(sCfg, "", nil)
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	config *Config,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		conn:         conn,
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		config:       config,
	}
	return s.setup(nil, hostname, negotiatedVersions)
}

func (s *session) setup(
	scfg *handshake.ServerConfig,
	hostname string,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	s.runClosed = make(chan struct{})
	s.handshakeCompleteChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)

	s.timer = time.NewTimer(0)
	s.sessionCreationTime = time.Now()

	s.rttStats = &congestion.RTTStats{}
	s.connectionParameters = handshake.NewConnectionParamatersManager(s.perspective, s.version)
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(s.rttStats)
	s.flowControlManager = flowcontrol.NewFlowControlManager(s.connectionParameters, s.rttStats)
	receivedPacketHandler := ackhandler.NewReceivedPacketHandler(s.ackAlarmChanged)
	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)

	var err error
	if s.perspective == protocol.PerspectiveServer {
		cryptoStream, _ := s.GetOrOpenStream(1)
		_, _ = s.AcceptStream() // don't expose the crypto stream
		verifySourceAddr := func(clientAddr net.Addr, hstk *handshake.STK) bool {
			var stk *STK
			if hstk != nil {
				stk = &STK{remoteAddr: hstk.RemoteAddr, sentTime: hstk.SentTime}
			}
			return s.config.AcceptSTK(clientAddr, stk)
		}
		s.cryptoSetup, err = newCryptoSetup(
			s.connectionID,
			s.conn.RemoteAddr(),
			s.version,
			scfg,
			cryptoStream,
			s.connectionParameters,
			s.config.Versions,
			verifySourceAddr,
			aeadChanged,
		)
	} else {
		cryptoStream, _ := s.OpenStream()
		s.cryptoSetup, err = newCryptoSetupClient(
			hostname,
			s.connectionID,
			s.version,
			cryptoStream,
			s.config.TLSConfig,
			s.connectionParameters,
			aeadChanged,
			&handshake.TransportParameters{RequestConnectionIDTruncation: s.config.RequestConnectionIDTruncation},
			negotiatedVersions,
		)
	}
	if err != nil {
		return nil, nil, err
	}

	streamFramer := newStreamFramer(s.streamsMap, s.flowControlManager)

	packer := newPacketPacker(s.connectionID, s.cryptoSetup, s.connectionParameters, streamFramer,
		s.perspective, s.version)
	s.sessionSender = newSessionSender(s.conn, s.sentPacketHandler, receivedPacketHandler,
		streamFramer, packer, s.flowControlManager)

	unpacker := &packetUnpacker{aead: s.cryptoSetup, version: s.version}
	s.sessionReceiver = newSessionReceiver(s.perspective, s.conn, s.sentPacketHandler,
		receivedPacketHandler, s.streamsMap, streamFramer, unpacker, s.cryptoSetup,
		s.flowControlManager, s.closeRemote)

	return s, handshakeChan, nil
}

// run the session main loop
func (s *session) run() error {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	aeadChanged := s.aeadChanged

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		select {
		case closeErr = <-s.closeChan:
			break runLoop
		case <-s.timer.C:
			s.timerRead = true
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err := s.sessionReceiver.handlePacketImpl(p)
			if err != nil {
				if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
					s.tryQueueingUndecryptablePacket(p)
					continue
				}
				s.closeLocal(err)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
		case l, ok := <-aeadChanged:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				s.handshakeComplete = true
				aeadChanged = nil // prevent this case from ever being selected again
				close(s.handshakeChan)
				close(s.handshakeCompleteChan)
			} else {
				if l == protocol.EncryptionForwardSecure {
					s.sessionSender.packer.SetForwardSecure()
				}
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}

		now := time.Now()
		if s.sentPacketHandler.GetAlarmTimeout().Before(now) {
			// This could cause packets to be retransmitted, so check it before trying
			// to send packets.
			s.sentPacketHandler.OnAlarm()
		}

		if err := s.sessionSender.sendPacket(); err != nil {
			s.closeLocal(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if now.Sub(s.sessionReceiver.lastNetworkActivityTime) >= s.idleTimeout() {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
		}
		s.garbageCollectStreams()
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeCompleteChan <- closeErr.err
		s.handshakeChan <- handshakeEvent{err: closeErr.err}
	}
	s.handleCloseError(closeErr)
	close(s.runClosed)
	return closeErr.err
}

func (s *session) maybeResetTimer() {
	nextDeadline := s.sessionReceiver.lastNetworkActivityTime.Add(s.idleTimeout())

	if !s.sessionSender.getNextAckScheduledTime().IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.sessionSender.getNextAckScheduledTime())
	}
	if lossTime := s.sentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, lossTime)
	}
	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(s.config.HandshakeTimeout)
		nextDeadline = utils.MinTime(nextDeadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}

	if nextDeadline.Equal(s.currentDeadline) {
		// No need to reset the timer
		return
	}

	// We need to drain the timer if the value from its channel was not read yet.
	// See https://groups.google.com/forum/#!topic/golang-dev/c9UUfASVPoU
	if !s.timer.Stop() && !s.timerRead {
		<-s.timer.C
	}
	s.timer.Reset(nextDeadline.Sub(time.Now()))

	s.timerRead = false
	s.currentDeadline = nextDeadline
}

func (s *session) idleTimeout() time.Duration {
	if s.handshakeComplete {
		return s.connectionParameters.GetIdleConnectionStateLifetime()
	}
	return protocol.InitialIdleTimeout
}

// handlePacket is called by the server with a new packet
func (s *session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *session) close(e error, remoteClose bool) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: remoteClose}
	})
}

func (s *session) closeLocal(e error) {
	s.close(e, false)
}

func (s *session) closeRemote(e error) {
	s.close(e, true)
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	s.close(e, false)
	<-s.runClosed
	return nil
}

func (s *session) handleCloseError(closeErr closeError) error {
	if closeErr.err == nil {
		closeErr.err = qerr.PeerGoingAway
	}

	var quicErr *qerr.QuicError
	var ok bool
	if quicErr, ok = closeErr.err.(*qerr.QuicError); !ok {
		quicErr = qerr.ToQuicError(closeErr.err)
	}
	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", closeErr.err.Error())
	}

	s.streamsMap.CloseWithError(quicErr)

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure || quicErr == handshake.ErrHOLExperiment {
		return s.sendPublicReset(s.sessionReceiver.getLastRcvdPacketNumber())
	}
	return s.sessionSender.sendConnectionClose(quicErr)
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenStream(id)
	if str != nil {
		return str, err
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) WaitUntilHandshakeComplete() error {
	return <-s.handshakeCompleteChan
}

func (s *session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.sessionSender.packer.QueueControlFrameForNextPacket(&frames.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	})
	s.scheduleSending()
}

func (s *session) newStream(id protocol.StreamID) (*stream, error) {
	stream, err := newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
	if err != nil {
		return nil, err
	}

	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}

	return stream, nil
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *session) garbageCollectStreams() {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		id := str.StreamID()
		if str.finished() {
			err := s.streamsMap.RemoveStream(id)
			if err != nil {
				return false, err
			}
			s.flowControlManager.RemoveStream(id)
		}
		return true, nil
	})
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.Write(writePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.handshakeComplete {
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.publicHeader.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) ackAlarmChanged(t time.Time) {
	s.sessionSender.setNextAckScheduledTime(t)
	s.maybeResetTimer()
}

func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
