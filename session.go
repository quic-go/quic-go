package quic

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

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

	streamCallback StreamCallback
	closeCallback  closeCallback

	conn connection

	streams          map[protocol.StreamID]*stream
	openStreamsCount uint32
	streamsMutex     sync.RWMutex

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	stopWaitingManager    ackhandler.StopWaitingManager
	windowUpdateManager   *windowUpdateManager
	blockedManager        *blockedManager

	flowController flowcontrol.FlowController // connection level flow controller

	unpacker *packetUnpacker
	packer   *packetPacker

	cryptoSetup *handshake.CryptoSetup

	receivedPackets  chan receivedPacket
	sendingScheduled chan struct{}
	closeChan        chan struct{}
	closed           uint32 // atomic bool

	undecryptablePackets []receivedPacket
	aeadChanged          chan struct{}

	smallPacketDelayedOccurranceTime time.Time

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
	stopWaitingManager := ackhandler.NewStopWaitingManager()
	connectionParametersManager := handshake.NewConnectionParamatersManager()

	session := &Session{
		connectionID:                connectionID,
		conn:                        conn,
		streamCallback:              streamCallback,
		closeCallback:               closeCallback,
		streams:                     make(map[protocol.StreamID]*stream),
		sentPacketHandler:           ackhandler.NewSentPacketHandler(stopWaitingManager),
		receivedPacketHandler:       ackhandler.NewReceivedPacketHandler(),
		stopWaitingManager:          stopWaitingManager,
		flowController:              flowcontrol.NewFlowController(0, connectionParametersManager),
		windowUpdateManager:         newWindowUpdateManager(),
		blockedManager:              newBlockedManager(),
		receivedPackets:             make(chan receivedPacket, protocol.MaxSessionUnprocessedPackets),
		closeChan:                   make(chan struct{}, 1),
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

	session.packer = newPacketPacker(connectionID, session.cryptoSetup, session.sentPacketHandler, session.connectionParametersManager, session.blockedManager, v)
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
		case <-s.closeChan:
			return
		default:
		}

		s.maybeResetTimer()

		var err error
		select {
		case <-s.closeChan:
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
		case <-s.aeadChanged:
			s.tryDecryptingQueuedPackets()
		}

		if err != nil {
			s.Close(err)
		}

		if err := s.maybeSendPacket(); err != nil {
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

	if !s.smallPacketDelayedOccurranceTime.IsZero() {
		// nextDeadline = utils.MinDuration(firstTimeout, s.smallPacketDelayedOccurranceTime.Add(protocol.SmallPacketSendDelay).Sub(now))
		nextDeadline = utils.MinTime(nextDeadline, s.smallPacketDelayedOccurranceTime.Add(protocol.SmallPacketSendDelay))
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
	r := bytes.NewReader(data)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.lastRcvdPacketNumber,
		hdr.PacketNumber,
	)
	s.lastRcvdPacketNumber = hdr.PacketNumber
	if utils.Debug() {
		utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, r.Size()+int64(len(hdr.Raw)), hdr.ConnectionID)
	}

	// TODO: Only do this after authenticating
	s.conn.setCurrentRemoteAddr(remoteAddr)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, r)
	if err != nil {
		return err
	}

	s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.entropyBit)

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
	if frame.StreamID == 0 {
		updated := s.flowController.UpdateSendWindow(frame.ByteOffset)
		if updated {
			s.blockedManager.RemoveBlockedStream(0)
		}
		s.streamsMutex.RLock()
		// tell all streams that the connection-level was updated
		for _, stream := range s.streams {
			if stream != nil {
				stream.ConnectionFlowControlWindowUpdated()
			}
		}
		s.streamsMutex.RUnlock()
	} else {
		s.streamsMutex.RLock()
		defer s.streamsMutex.RUnlock()
		stream, streamExists := s.streams[frame.StreamID]
		if !streamExists {
			return errWindowUpdateOnInvalidStream
		}
		if stream == nil {
			return errWindowUpdateOnClosedStream
		}

		updated := stream.UpdateSendFlowControlWindow(frame.ByteOffset)
		if updated {
			s.blockedManager.RemoveBlockedStream(frame.StreamID)
		}
	}

	return nil
}

// TODO: Handle frame.byteOffset
func (s *Session) handleRstStreamFrame(frame *frames.RstStreamFrame) error {
	s.streamsMutex.RLock()
	str, streamExists := s.streams[frame.StreamID]
	s.streamsMutex.RUnlock()
	if !streamExists || str == nil {
		return errRstStreamOnInvalidStream
	}
	str.RegisterError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return nil
}

func (s *Session) handleAckFrame(frame *frames.AckFrame) error {
	if err := s.sentPacketHandler.ReceivedAck(frame); err != nil {
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
	s.closeChan <- struct{}{}

	if e == nil {
		e = qerr.PeerGoingAway
	}

	utils.Errorf("Closing session with error: %s", e.Error())
	s.closeStreamsWithError(e)
	s.closeCallback(s.connectionID)

	if remoteClose {
		return nil
	}

	quicErr := qerr.ToQuicError(e)
	if quicErr.ErrorCode == qerr.DecryptionFailure {
		return s.sendPublicReset(s.lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *Session) closeStreamsWithError(err error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	for _, s := range s.streams {
		if s == nil {
			continue
		}
		s.RegisterError(err)
	}
}

// TODO: try sending more than one packet
func (s *Session) maybeSendPacket() error {
	if !s.smallPacketDelayedOccurranceTime.IsZero() && time.Now().Sub(s.smallPacketDelayedOccurranceTime) > protocol.SmallPacketSendDelay {
		return s.sendPacket()
	}

	// always send out retransmissions immediately. No need to check the size of the packet
	// in the edge cases where a belated ACK was received for a packet that was already queued for retransmission, we might send out a small packet. However, this shouldn't happen very often
	if s.sentPacketHandler.ProbablyHasPacketForRetransmission() {
		return s.sendPacket()
	}

	if !s.sentPacketHandler.CongestionAllowsSending() {
		return nil
	}

	var maxPacketSize protocol.ByteCount // the maximum size of a packet we could send out at this moment

	// we only estimate the size of the StopWaitingFrame here
	stopWaitingFrame := s.stopWaitingManager.GetStopWaitingFrame()
	if stopWaitingFrame != nil {
		// The actual size of a StopWaitingFrame depends on the packet number of the packet it is sent with, and it's easier here to neglect the fact the StopWaitingFrame could be 5 bytes smaller than calculated here
		maxPacketSize += 8
	}

	ack, err := s.receivedPacketHandler.GetAckFrame(false)
	if err != nil {
		return err
	}

	if ack != nil {
		ackLength, _ := ack.MinLength() // MinLength never errors for an ACK frame
		maxPacketSize += ackLength
	}

	// note that maxPacketSize can get (much) larger than protocol.MaxPacketSize if there is a long queue of StreamFrames
	maxPacketSize += s.packer.StreamFrameQueueByteLen()

	if maxPacketSize > protocol.SmallPacketPayloadSizeThreshold {
		return s.sendPacket()
	}

	if maxPacketSize == 0 {
		return nil
	}

	if s.smallPacketDelayedOccurranceTime.IsZero() {
		s.smallPacketDelayedOccurranceTime = time.Now()
	}

	return nil
}

func (s *Session) sendPacket() error {
	s.smallPacketDelayedOccurranceTime = time.Time{} // zero

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
			s.packer.AddHighPrioStreamFrame(*streamFrame)
		}
	}

	windowUpdateFrames := s.windowUpdateManager.GetWindowUpdateFrames()

	for _, wuf := range windowUpdateFrames {
		controlFrames = append(controlFrames, wuf)
	}

	ack, err := s.receivedPacketHandler.GetAckFrame(true)
	if err != nil {
		return err
	}
	if ack != nil {
		controlFrames = append(controlFrames, ack)
	}

	stopWaitingFrame := s.stopWaitingManager.GetStopWaitingFrame()
	packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames)

	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}

	err = s.sentPacketHandler.SentPacket(&ackhandler.Packet{
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

	err = s.conn.write(packet.raw)
	if err != nil {
		return err
	}

	if !s.packer.Empty() {
		s.scheduleSending()
	}

	return nil
}

func (s *Session) sendConnectionClose(quicErr *qerr.QuicError) error {
	packet, err := s.packer.PackConnectionClose(&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage})
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

// queueStreamFrame queues a frame for sending to the client
func (s *Session) queueStreamFrame(frame *frames.StreamFrame) error {
	s.packer.AddStreamFrame(*frame)
	s.scheduleSending()
	return nil
}

// updateReceiveFlowControlWindow updates the flow control window for a stream
func (s *Session) updateReceiveFlowControlWindow(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	s.windowUpdateManager.SetStreamOffset(streamID, byteOffset)
	return nil
}

func (s *Session) streamBlocked(streamID protocol.StreamID, byteOffset protocol.ByteCount) {
	s.packer.AddBlocked(streamID, byteOffset)
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
	stream, err := newStream(s, s.connectionParametersManager, s.flowController, id)
	if err != nil {
		return nil, err
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
		if v.finishedWriting() {
			s.blockedManager.RemoveBlockedStream(k)
		}
		if v.finishedReading() {
			s.windowUpdateManager.RemoveStream(k)
		}
		if v.finished() {
			utils.Debugf("Garbage-collecting stream %d", k)
			atomic.AddUint32(&s.openStreamsCount, ^uint32(0)) // decrement
			s.streams[k] = nil
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
