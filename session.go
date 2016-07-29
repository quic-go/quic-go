package quic

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/ackhandlerlegacy"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *publicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   interface{}
	publicHeader *publicHeader
	data         []byte
}

var (
	errRstStreamOnInvalidStream    = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnInvalidStream = qerr.Error(qerr.InvalidWindowUpdateData, "WINDOW_UPDATE received for unknown stream")
	errWindowUpdateOnClosedStream  = errors.New("WINDOW_UPDATE received for an already closed stream")
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, utils.Stream)

// closeCallback is called when a session is closed
type closeCallback func(id protocol.ConnectionID)

// A Session is a QUIC session
type Session struct {
	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	streamCallback StreamCallback
	closeCallback  closeCallback

	conn connection

	streams          map[protocol.StreamID]*stream
	openStreamsCount uint32
	streamsMutex     sync.RWMutex

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	stopWaitingManager    ackhandler.StopWaitingManager
	streamFramer          *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	cryptoSetup *handshake.CryptoSetup

	receivedPackets  chan receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	// If the value is not nil, the error is sent as a CONNECTION_CLOSE.
	closeChan chan *qerr.QuicError
	closed    uint32 // atomic bool

	undecryptablePackets []receivedPacket
	aeadChanged          chan struct{}

	delayedAckOriginTime time.Time

	connectionParametersManager *handshake.ConnectionParametersManager

	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	lastRcvdPacketNumber protocol.PacketNumber

	lastNetworkActivityTime time.Time

	timer           *time.Timer
	currentDeadline time.Time
	timerRead       bool
}

// newSession makes a new session
func newSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback closeCallback) (packetHandler, error) {
	connectionParametersManager := handshake.NewConnectionParamatersManager()
	flowControlManager := flowcontrol.NewFlowControlManager(connectionParametersManager)

	var stopWaitingManager ackhandler.StopWaitingManager
	var sentPacketHandler ackhandler.SentPacketHandler
	var receivedPacketHandler ackhandler.ReceivedPacketHandler

	if v <= protocol.Version33 {
		stopWaitingManager = ackhandlerlegacy.NewStopWaitingManager().(ackhandler.StopWaitingManager)
		sentPacketHandler = ackhandlerlegacy.NewSentPacketHandler(stopWaitingManager).(ackhandler.SentPacketHandler)
		receivedPacketHandler = ackhandlerlegacy.NewReceivedPacketHandler().(ackhandler.ReceivedPacketHandler)
	} else {
		stopWaitingManager = ackhandler.NewStopWaitingManager()
		sentPacketHandler = ackhandler.NewSentPacketHandler(stopWaitingManager)
		receivedPacketHandler = ackhandler.NewReceivedPacketHandler()
	}

	session := &Session{
		connectionID:                connectionID,
		version:                     v,
		conn:                        conn,
		streamCallback:              streamCallback,
		closeCallback:               closeCallback,
		streams:                     make(map[protocol.StreamID]*stream),
		sentPacketHandler:           sentPacketHandler,
		receivedPacketHandler:       receivedPacketHandler,
		stopWaitingManager:          stopWaitingManager,
		flowControlManager:          flowControlManager,
		receivedPackets:             make(chan receivedPacket, protocol.MaxSessionUnprocessedPackets),
		closeChan:                   make(chan *qerr.QuicError, 1),
		sendingScheduled:            make(chan struct{}, 1),
		connectionParametersManager: connectionParametersManager,
		undecryptablePackets:        make([]receivedPacket, 0, protocol.MaxUndecryptablePackets),
		aeadChanged:                 make(chan struct{}, 1),
		timer:                       time.NewTimer(0),
		lastNetworkActivityTime: time.Now(),
	}

	cryptoStream, _ := session.OpenStream(1)
	var err error
	session.cryptoSetup, err = handshake.NewCryptoSetup(connectionID, conn.IP(), v, sCfg, cryptoStream, session.connectionParametersManager, session.aeadChanged)
	if err != nil {
		return nil, err
	}

	session.streamFramer = newStreamFramer(&session.streams, &session.streamsMutex, flowControlManager)
	session.packer = newPacketPacker(connectionID, session.cryptoSetup, session.connectionParametersManager, session.streamFramer, v)
	session.unpacker = &packetUnpacker{aead: session.cryptoSetup, version: v}

	return session, err
}

// run the session main loop
func (s *Session) run() {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	for {
		// Close immediately if requested
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			return
		default:
		}

		s.maybeResetTimer()

		var err error
		select {
		case errForConnClose := <-s.closeChan:
			if errForConnClose != nil {
				s.sendConnectionClose(errForConnClose)
			}
			return
		case <-s.timer.C:
			s.timerRead = true
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err = s.handlePacketImpl(p.remoteAddr, p.publicHeader, p.data)
			if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
				s.tryQueueingUndecryptablePacket(p)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
			if s.delayedAckOriginTime.IsZero() {
				s.delayedAckOriginTime = time.Now()
			}
		case <-s.aeadChanged:
			s.tryDecryptingQueuedPackets()
		}

		if err != nil {
			s.Close(err)
		}

		if err := s.sendPacket(); err != nil {
			s.Close(err)
		}
		if time.Now().Sub(s.lastNetworkActivityTime) >= s.connectionParametersManager.GetIdleConnectionStateLifetime() {
			s.Close(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}
		s.garbageCollectStreams()
	}
}

func (s *Session) maybeResetTimer() {
	nextDeadline := s.lastNetworkActivityTime.Add(s.connectionParametersManager.GetIdleConnectionStateLifetime())

	if !s.delayedAckOriginTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, s.delayedAckOriginTime.Add(protocol.AckSendDelay))
	}
	if rtoTime := s.sentPacketHandler.TimeOfFirstRTO(); !rtoTime.IsZero() {
		nextDeadline = utils.MinTime(nextDeadline, rtoTime)
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

func (s *Session) handlePacketImpl(remoteAddr interface{}, hdr *publicHeader, data []byte) error {
	s.lastNetworkActivityTime = time.Now()

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.lastRcvdPacketNumber,
		hdr.PacketNumber,
	)
	s.lastRcvdPacketNumber = hdr.PacketNumber
	if utils.Debug() {
		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID)
	}

	// TODO: Only do this after authenticating
	s.conn.setCurrentRemoteAddr(remoteAddr)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, data)
	if err != nil {
		return err
	}

	err = s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.entropyBit)
	// ignore duplicate packets
	if err == ackhandlerlegacy.ErrDuplicatePacket || err == ackhandler.ErrDuplicatePacket {
		return nil
	}
	// ignore packets with packet numbers smaller than the LeastUnacked of a StopWaiting
	if err == ackhandlerlegacy.ErrPacketSmallerThanLastStopWaiting || err == ackhandler.ErrPacketSmallerThanLastStopWaiting {
		return nil
	}

	if err != nil {
		return err
	}

	return s.handleFrames(packet.frames)
}

func (s *Session) handleFrames(fs []frames.Frame) error {
	for _, ff := range fs {
		var err error
		frames.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
			// TODO: send RstStreamFrame
		case *frames.AckFrame:
			err = s.handleAckFrame(frame)
		case *frames.ConnectionCloseFrame:
			s.closeImpl(qerr.Error(frame.ErrorCode, frame.ReasonPhrase), true)
		case *frames.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *frames.StopWaitingFrame:
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
		case *frames.PingFrame:
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandlerlegacy.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

// handlePacket handles a packet
func (s *Session) handlePacket(remoteAddr interface{}, hdr *publicHeader, data []byte) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	select {
	case s.receivedPackets <- receivedPacket{remoteAddr: remoteAddr, publicHeader: hdr, data: data}:
	default:
	}
}

func (s *Session) handleStreamFrame(frame *frames.StreamFrame) error {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	str, streamExists := s.streams[frame.StreamID]

	var err error
	if !streamExists {
		if !s.isValidStreamID(frame.StreamID) {
			return qerr.InvalidStreamID
		}

		str, err = s.newStreamImpl(frame.StreamID)
		if err != nil {
			return err
		}
	}
	if str == nil {
		// Stream is closed, ignore
		return nil
	}
	err = str.AddStreamFrame(frame)
	if err != nil {
		return err
	}
	if !streamExists {
		s.streamCallback(s, str)
	}
	return nil
}

func (s *Session) isValidStreamID(streamID protocol.StreamID) bool {
	return streamID%2 == 1
}

func (s *Session) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	s.streamsMutex.RLock()
	defer s.streamsMutex.RUnlock()
	if frame.StreamID != 0 {
		stream, ok := s.streams[frame.StreamID]
		if ok && stream == nil {
			return errWindowUpdateOnClosedStream
		}

		// open new stream when receiving a WindowUpdate for a non-existing stream
		// this can occur if the client immediately sends a WindowUpdate for a newly opened stream, and packet reordering occurs such that the packet opening the new stream arrives after the WindowUpdate
		if !ok {
			s.newStreamImpl(frame.StreamID)
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

// TODO: Handle frame.byteOffset
func (s *Session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	s.streamsMutex.RLock()
	str, streamExists := s.streams[frame.StreamID]
	s.streamsMutex.RUnlock()
	if !streamExists || str == nil {
		return errRstStreamOnInvalidStream
	}
	s.closeStreamWithError(str, fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return nil
}

func (s *Session) handleAckFrame(frame *frames.AckFrame) error {
	if err := s.sentPacketHandler.ReceivedAck(frame, s.lastRcvdPacketNumber); err != nil {
		return err
	}
	return nil
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
func (s *Session) Close(e error) error {
	return s.closeImpl(e, false)
}

func (s *Session) closeImpl(e error, remoteClose bool) error {
	// Only close once
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return nil
	}

	if e == nil {
		e = qerr.PeerGoingAway
	}

	quicErr := qerr.ToQuicError(e)

	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", e.Error())
	}

	s.closeStreamsWithError(quicErr)
	s.closeCallback(s.connectionID)

	if remoteClose {
		// If this is a remote close we don't need to send a CONNECTION_CLOSE
		s.closeChan <- nil
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure {
		// If we send a public reset, don't send a CONNECTION_CLOSE
		s.closeChan <- nil
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	s.closeChan <- quicErr
	return nil
}

func (s *Session) closeStreamsWithError(err error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	for _, str := range s.streams {
		if str == nil {
			continue
		}
		s.closeStreamWithError(str, err)
	}
}

func (s *Session) closeStreamWithError(str *stream, err error) {
	str.RegisterError(err)
}

func (s *Session) sendPacket() error {
	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	for {
		err := s.sentPacketHandler.CheckForError()
		if err != nil {
			return err
		}

		if !s.sentPacketHandler.CongestionAllowsSending() {
			return nil
		}

		var controlFrames []frames.Frame

		// check for retransmissions first
		for {
			retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket == nil {
				break
			}
			utils.Debugf("\tDequeueing retransmission for packet 0x%x", retransmitPacket.PacketNumber)
			s.stopWaitingManager.RegisterPacketForRetransmission(retransmitPacket)
			// resend the frames that were in the packet
			controlFrames = append(controlFrames, retransmitPacket.GetControlFramesForRetransmission()...)
			for _, streamFrame := range retransmitPacket.GetStreamFramesForRetransmission() {
				s.streamFramer.AddFrameForRetransmission(streamFrame)
			}
		}

		windowUpdateFrames, err := s.getWindowUpdateFrames()
		if err != nil {
			return err
		}

		for _, wuf := range windowUpdateFrames {
			controlFrames = append(controlFrames, wuf)
		}

		ack, err := s.receivedPacketHandler.GetAckFrame(false)
		if err != nil {
			return err
		}
		if ack != nil {
			controlFrames = append(controlFrames, ack)
		}

		// Check whether we are allowed to send a packet containing only an ACK
		maySendOnlyAck := time.Now().Sub(s.delayedAckOriginTime) > protocol.AckSendDelay

		stopWaitingFrame := s.stopWaitingManager.GetStopWaitingFrame()
		packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, s.sentPacketHandler.GetLargestAcked(), maySendOnlyAck)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}

		// Pop the ACK frame now that we are sure we're gonna send it
		_, err = s.receivedPacketHandler.GetAckFrame(true)
		if err != nil {
			return err
		}

		for _, f := range windowUpdateFrames {
			s.packer.QueueControlFrameForNextPacket(f)
		}

		err = s.sentPacketHandler.SentPacket(&ackhandlerlegacy.Packet{
			PacketNumber: packet.number,
			Frames:       packet.frames,
			EntropyBit:   packet.entropyBit,
			Length:       protocol.ByteCount(len(packet.raw)),
		})
		if err != nil {
			return err
		}
		s.stopWaitingManager.SentStopWaitingWithPacket(packet.number)
		s.logPacket(packet)
		s.delayedAckOriginTime = time.Time{}

		err = s.conn.write(packet.raw)
		putPacketBuffer(packet.raw)
		if err != nil {
			return err
		}
	}
}

func (s *Session) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage}, s.sentPacketHandler.GetLargestAcked())
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected packet not to be nil")
	}
	s.logPacket(packet)
	return s.conn.write(packet.raw)
}

func (s *Session) logPacket(packet *packedPacket) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	if utils.Debug() {
		utils.Debugf("-> Sending packet 0x%x (%d bytes)", packet.number, len(packet.raw))
		for _, frame := range packet.frames {
			frames.LogFrame(frame, true)
		}
	}
}

// OpenStream creates a new stream open for reading and writing
func (s *Session) OpenStream(id protocol.StreamID) (utils.Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	return s.newStreamImpl(id)
}

// GetOrOpenStream returns an existing stream with the given id, or opens a new stream
func (s *Session) GetOrOpenStream(id protocol.StreamID) (utils.Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	if stream, ok := s.streams[id]; ok {
		return stream, nil
	}
	return s.newStreamImpl(id)
}

// The streamsMutex is locked by OpenStream or GetOrOpenStream before calling this function.
func (s *Session) newStreamImpl(id protocol.StreamID) (*stream, error) {
	maxAllowedStreams := uint32(protocol.MaxStreamsMultiplier * float32(s.connectionParametersManager.GetMaxStreamsPerConnection()))
	if atomic.LoadUint32(&s.openStreamsCount) >= maxAllowedStreams {
		go s.Close(qerr.TooManyOpenStreams)
		return nil, qerr.TooManyOpenStreams
	}
	if _, ok := s.streams[id]; ok {
		return nil, fmt.Errorf("Session: stream with ID %d already exists", id)
	}
	stream, err := newStream(s.scheduleSending, s.connectionParametersManager, s.flowControlManager, id)
	if err != nil {
		return nil, err
	}

	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}

	atomic.AddUint32(&s.openStreamsCount, 1)
	s.streams[id] = stream
	return stream, nil
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *Session) garbageCollectStreams() {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	for k, v := range s.streams {
		if v == nil {
			continue
		}
		if v.finished() {
			utils.Debugf("Garbage-collecting stream %d", k)
			atomic.AddUint32(&s.openStreamsCount, ^uint32(0)) // decrement
			s.streams[k] = nil
			s.flowControlManager.RemoveStream(k)
		}
	}
}

func (s *Session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	return s.conn.write(writePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *Session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *Session) tryQueueingUndecryptablePacket(p receivedPacket) {
	utils.Debugf("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	if len(s.undecryptablePackets)+1 >= protocol.MaxUndecryptablePackets {
		s.Close(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
	}
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *Session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p.remoteAddr, p.publicHeader, p.data)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *Session) getWindowUpdateFrames() ([]*frames.WindowUpdateFrame, error) {
	s.streamsMutex.RLock()
	defer s.streamsMutex.RUnlock()

	var res []*frames.WindowUpdateFrame

	for id, str := range s.streams {
		if str == nil {
			continue
		}

		doUpdate, offset, err := s.flowControlManager.MaybeTriggerStreamWindowUpdate(id)
		if err != nil {
			return nil, err
		}
		if doUpdate {
			res = append(res, &frames.WindowUpdateFrame{StreamID: id, ByteOffset: offset})
		}
	}

	doUpdate, offset := s.flowControlManager.MaybeTriggerConnectionWindowUpdate()
	if doUpdate {
		res = append(res, &frames.WindowUpdateFrame{StreamID: 0, ByteOffset: offset})
	}

	return res, nil
}
