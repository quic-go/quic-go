package quic

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
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
	errReopeningStreamsNotAllowed  = errors.New("Reopening Streams not allowed")
	errRstStreamOnInvalidStream    = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnInvalidStream = errors.New("WINDOW_UPDATE received for unknown stream")
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

	streams      map[protocol.StreamID]*stream
	streamsMutex sync.RWMutex

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	stopWaitingManager    ackhandler.StopWaitingManager
	windowUpdateManager   *windowUpdateManager

	unpacker *packetUnpacker
	packer   *packetPacker

	receivedPackets  chan receivedPacket
	sendingScheduled chan struct{}
	closeChan        chan struct{}
	closed           bool

	undecryptablePackets []receivedPacket
	aeadChanged          chan struct{}

	smallPacketDelayedOccurranceTime time.Time

	connectionParametersManager *handshake.ConnectionParametersManager

	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	lastRcvdPacketNumber protocol.PacketNumber

	rttStats   congestion.RTTStats
	congestion congestion.SendAlgorithm
}

// newSession makes a new session
func newSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback closeCallback) packetHandler {
	stopWaitingManager := ackhandler.NewStopWaitingManager()
	session := &Session{
		connectionID:                connectionID,
		conn:                        conn,
		streamCallback:              streamCallback,
		closeCallback:               closeCallback,
		streams:                     make(map[protocol.StreamID]*stream),
		sentPacketHandler:           ackhandler.NewSentPacketHandler(stopWaitingManager),
		receivedPacketHandler:       ackhandler.NewReceivedPacketHandler(),
		stopWaitingManager:          stopWaitingManager,
		windowUpdateManager:         newWindowUpdateManager(),
		receivedPackets:             make(chan receivedPacket, 1000), // TODO: What if server receives many packets and connection is already closed?!
		closeChan:                   make(chan struct{}, 1),
		sendingScheduled:            make(chan struct{}, 1),
		rttStats:                    congestion.RTTStats{},
		connectionParametersManager: handshake.NewConnectionParamatersManager(),
		undecryptablePackets:        make([]receivedPacket, 0, protocol.MaxUndecryptablePackets),
		aeadChanged:                 make(chan struct{}, 1),
	}

	cryptoStream, _ := session.OpenStream(1)
	cryptoSetup := handshake.NewCryptoSetup(connectionID, v, sCfg, cryptoStream, session.connectionParametersManager, session.aeadChanged)

	go func() {
		if err := cryptoSetup.HandleCryptoStream(); err != nil {
			session.Close(err, true)
		}
	}()

	session.packer = &packetPacker{
		aead: cryptoSetup,
		connectionParametersManager: session.connectionParametersManager,
		sentPacketHandler:           session.sentPacketHandler,
		connectionID:                connectionID,
		version:                     v,
	}
	session.unpacker = &packetUnpacker{aead: cryptoSetup, version: v}

	session.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		&session.rttStats,
		false, /* don't use reno since chromium doesn't (why?) */
		protocol.InitialCongestionWindow,
		protocol.DefaultMaxCongestionWindow,
	)

	return session
}

// run the session main loop
func (s *Session) run() {
	for {
		// Close immediately if requested
		select {
		case <-s.closeChan:
			return
		default:
		}

		// receive at a nil channel blocks forever
		var smallPacketSendTimer <-chan time.Time
		if !s.smallPacketDelayedOccurranceTime.IsZero() {
			smallPacketSendTimer = time.After(time.Now().Sub(s.smallPacketDelayedOccurranceTime))
		}

		var err error
		select {
		case <-s.closeChan:
			return
		case p := <-s.receivedPackets:
			err = s.handlePacketImpl(p.remoteAddr, p.publicHeader, p.data)
			if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
				s.tryQueueingUndecryptablePacket(p)
				continue
			}
			s.scheduleSending()
		case <-s.sendingScheduled:
			err = s.maybeSendPacket()
		case <-smallPacketSendTimer:
			err = s.sendPacket()
		case <-s.aeadChanged:
			s.tryDecryptingQueuedPackets()
		case <-time.After(s.connectionParametersManager.GetIdleConnectionStateLifetime()):
			s.Close(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."), true)
		}

		if err != nil {
			switch err {
			// Can happen e.g. when packets thought missing arrive late
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
			// Can happen when RST_STREAMs arrive early or late (?)
			case ackhandler.ErrMapAccess:
				s.Close(err, true) // TODO: sent correct error code here
			case errRstStreamOnInvalidStream:
				utils.Errorf("Ignoring error in session: %s", err.Error())
			// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			case errWindowUpdateOnClosedStream:
			// Can happen when the packet opening the stream was lost.
			case errWindowUpdateOnInvalidStream:
			default:
				s.Close(err, true)
			}
		}

		s.garbageCollectStreams()
	}
}

func (s *Session) handlePacketImpl(remoteAddr interface{}, hdr *publicHeader, data []byte) error {
	r := bytes.NewReader(data)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		s.lastRcvdPacketNumber,
		hdr.PacketNumber,
	)
	s.lastRcvdPacketNumber = hdr.PacketNumber
	utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x", hdr.PacketNumber, r.Size(), hdr.ConnectionID)

	// TODO: Only do this after authenticating
	s.conn.setCurrentRemoteAddr(remoteAddr)

	packet, err := s.unpacker.Unpack(hdr.Raw, hdr, r)
	if err != nil {
		return err
	}

	s.receivedPacketHandler.ReceivedPacket(hdr.PacketNumber, packet.entropyBit)

	for _, ff := range packet.frames {
		var err error
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			utils.Debugf("\t<- &frames.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", frame.StreamID, frame.FinBit, frame.Offset, len(frame.Data), frame.Offset+protocol.ByteCount(len(frame.Data)))
			err = s.handleStreamFrame(frame)
			// TODO: send error for flow control violation
			// TODO: send RstStreamFrame
		case *frames.AckFrame:
			err = s.handleAckFrame(frame)
		case *frames.ConnectionCloseFrame:
			// ToDo: send right error in ConnectionClose frame
			utils.Debugf("\t<- %#v", frame)
			s.Close(nil, false)
		case *frames.StopWaitingFrame:
			utils.Debugf("\t<- %#v", frame)
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
			utils.Debugf("\t<- %#v", frame)
		case *frames.WindowUpdateFrame:
			utils.Debugf("\t<- %#v", frame)
			err = s.handleWindowUpdateFrame(frame)
		case *frames.BlockedFrame:
			utils.Infof("BLOCKED frame received for connection %x stream %d", s.connectionID, frame.StreamID)
		case *frames.PingFrame:
			utils.Debugf("\t<- %#v", frame)
		default:
			panic("unexpected frame type")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// handlePacket handles a packet
func (s *Session) handlePacket(remoteAddr interface{}, hdr *publicHeader, data []byte) {
	s.receivedPackets <- receivedPacket{remoteAddr: remoteAddr, publicHeader: hdr, data: data}
}

// TODO: Ignore data for closed streams
func (s *Session) handleStreamFrame(frame *frames.StreamFrame) error {
	s.streamsMutex.RLock()
	str, streamExists := s.streams[frame.StreamID]
	s.streamsMutex.RUnlock()

	if !streamExists {
		if !s.isValidStreamID(frame.StreamID) {
			return qerr.InvalidStreamID
		}

		ss, _ := s.OpenStream(frame.StreamID)
		str = ss.(*stream)
	}
	if str == nil {
		return errReopeningStreamsNotAllowed
	}
	err := str.AddStreamFrame(frame)
	if err != nil {
		return err
	}
	if !streamExists {
		s.streamCallback(s, str)
	}
	return nil
}

func (s *Session) isValidStreamID(streamID protocol.StreamID) bool {
	if streamID%2 != 1 {
		return false
	}
	return true
}

func (s *Session) handleWindowUpdateFrame(frame *frames.WindowUpdateFrame) error {
	if frame.StreamID == 0 {
		// TODO: handle connection level WindowUpdateFrames
		// return errors.New("Connection level flow control not yet implemented")
		return nil
	}
	s.streamsMutex.RLock()
	defer s.streamsMutex.RUnlock()

	stream, streamExists := s.streams[frame.StreamID]

	if !streamExists {
		return errWindowUpdateOnInvalidStream
	}
	if stream == nil {
		return errWindowUpdateOnClosedStream
	}

	stream.UpdateSendFlowControlWindow(frame.ByteOffset)

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
	duration, acked, lost, err := s.sentPacketHandler.ReceivedAck(frame)
	if err != nil {
		return err
	}

	// TODO: Don't always update RTT
	s.rttStats.UpdateRTT(duration, frame.DelayTime, time.Now())

	cAcked := make(congestion.PacketVector, len(acked))
	for i, v := range acked {
		cAcked[i].Number = v.PacketNumber
		cAcked[i].Length = v.Length
	}
	cLost := make(congestion.PacketVector, len(lost))
	for i, v := range lost {
		cLost[i].Number = v.PacketNumber
		cLost[i].Length = v.Length
	}
	s.congestion.OnCongestionEvent(
		true, /* rtt updated */
		s.sentPacketHandler.BytesInFlight(),
		cAcked,
		cLost,
	)

	utils.Debugf("\t<- %#v", frame)
	utils.Debugf("\tEstimated RTT: %dms", s.rttStats.SmoothedRTT()/time.Millisecond)
	return nil
}

// Close the connection
func (s *Session) Close(e error, sendConnectionClose bool) error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeChan <- struct{}{}

	s.closeCallback(s.connectionID)

	if !sendConnectionClose {
		return nil
	}

	if e == nil {
		e = qerr.PeerGoingAway
	}

	utils.Errorf("Closing session with error: %s", e.Error())
	s.closeStreamsWithError(e)

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

func (s *Session) maybeSendPacket() error {
	if !s.congestionAllowsSending() {
		return nil
	}

	// always send out retransmissions immediately. No need to check the size of the packet
	if s.sentPacketHandler.HasPacketForRetransmission() {
		return s.sendPacket()
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

	if s.smallPacketDelayedOccurranceTime.IsZero() {
		s.smallPacketDelayedOccurranceTime = time.Now()
	}

	return nil
}

func (s *Session) sendPacket() error {
	if !s.congestionAllowsSending() {
		return nil
	}

	var controlFrames []frames.Frame

	// check for retransmissions first
	// TODO: handle multiple packets retransmissions
	retransmitPacket := s.sentPacketHandler.DequeuePacketForRetransmission()
	if retransmitPacket != nil {
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
	packet, err := s.packer.PackPacket(stopWaitingFrame, controlFrames, true)

	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}

	s.smallPacketDelayedOccurranceTime = time.Time{} // zero

	err = s.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber: packet.number,
		Frames:       packet.frames,
		EntropyBit:   packet.entropyBit,
		Length:       protocol.ByteCount(len(packet.raw)),
	})
	if err != nil {
		return err
	}

	s.congestion.OnPacketSent(
		time.Now(),
		s.sentPacketHandler.BytesInFlight(),
		packet.number,
		protocol.ByteCount(len(packet.raw)),
		true, /* TODO: is retransmittable */
	)

	s.stopWaitingManager.SentStopWaitingWithPacket(packet.number)

	utils.Debugf("-> Sending packet 0x%x (%d bytes)", packet.number, len(packet.raw))
	for _, frame := range packet.frames {
		if streamFrame, isStreamFrame := frame.(*frames.StreamFrame); isStreamFrame {
			utils.Debugf("\t-> &frames.StreamFrame{StreamID: %d, FinBit: %t, Offset: 0x%x, Data length: 0x%x, Offset + Data length: 0x%x}", streamFrame.StreamID, streamFrame.FinBit, streamFrame.Offset, len(streamFrame.Data), streamFrame.Offset+protocol.ByteCount(len(streamFrame.Data)))
		} else {
			utils.Debugf("\t-> %#v", frame)
		}
	}

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
	packet, err := s.packer.PackPacket(nil, []frames.Frame{
		&frames.ConnectionCloseFrame{ErrorCode: quicErr.ErrorCode, ReasonPhrase: quicErr.ErrorMessage},
	}, false)
	if err != nil {
		return err
	}
	if packet == nil {
		panic("Session: internal inconsistency: expected packet not to be nil")
	}
	return s.conn.write(packet.raw)
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

func (s *Session) newStreamImpl(id protocol.StreamID) (*stream, error) {
	stream, err := newStream(s, s.connectionParametersManager, id)
	if err != nil {
		return nil, err
	}
	if s.streams[id] != nil {
		return nil, fmt.Errorf("Session: stream with ID %d already exists", id)
	}
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
			s.streams[k] = nil
		}
	}
}

func (s *Session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	packet := &publicResetPacket{
		connectionID:         s.connectionID,
		rejectedPacketNumber: rejectedPacketNumber,
		nonceProof:           0, // TODO: Currently ignored by chrome.
	}
	var b bytes.Buffer
	packet.Write(&b)
	return s.conn.write(b.Bytes())
}

// scheduleSending signals that we have data for sending
func (s *Session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *Session) congestionAllowsSending() bool {
	return s.sentPacketHandler.BytesInFlight() <= s.congestion.GetCongestionWindow()
}

func (s *Session) tryQueueingUndecryptablePacket(p receivedPacket) {
	utils.Debugf("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	if len(s.undecryptablePackets)+1 >= protocol.MaxUndecryptablePackets {
		s.Close(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"), true)
	}
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *Session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p.remoteAddr, p.publicHeader, p.data)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}
