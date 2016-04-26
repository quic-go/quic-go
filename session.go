package quic

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/errorcodes"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type receivedPacket struct {
	remoteAddr   interface{}
	publicHeader *PublicHeader
	r            *bytes.Reader
}

var (
	errRstStreamOnInvalidStream = errors.New("RST_STREAM received for unknown stream")
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, utils.Stream)

// A Session is a QUIC session
type Session struct {
	streamCallback StreamCallback

	conn connection

	streams      map[protocol.StreamID]*stream
	streamsMutex sync.RWMutex

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	unpacker *packetUnpacker
	packer   *packetPacker

	receivedPackets chan receivedPacket
	closeChan       chan struct{}

	// Used to calculate the next packet number from the truncated wire representation
	lastRcvdPacketNumber protocol.PacketNumber
}

// NewSession makes a new session
func NewSession(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) PacketHandler {
	session := &Session{
		conn:                  conn,
		streamCallback:        streamCallback,
		streams:               make(map[protocol.StreamID]*stream),
		sentPacketHandler:     ackhandler.NewSentPacketHandler(),
		receivedPacketHandler: ackhandler.NewReceivedPacketHandler(),
		receivedPackets:       make(chan receivedPacket),
		closeChan:             make(chan struct{}),
	}

	cryptoStream, _ := session.NewStream(1)
	cryptoSetup := handshake.NewCryptoSetup(connectionID, v, sCfg, cryptoStream)
	go cryptoSetup.HandleCryptoStream()

	session.packer = &packetPacker{aead: cryptoSetup, connectionID: connectionID}
	session.unpacker = &packetUnpacker{aead: cryptoSetup}

	return session
}

// Run the session main loop
func (s *Session) Run() {
	sendTimeout := 1 * time.Millisecond
	for {
		var err error
		select {
		case <-s.closeChan:
			return
		case p := <-s.receivedPackets:
			err = s.handlePacket(p.remoteAddr, p.publicHeader, p.r)
		case <-time.After(sendTimeout):
			err = s.sendPacket()
		}

		if err != nil {
			switch err {
			// Can happen e.g. when packets thought missing arrive late
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
			// Can happen when RST_STREAMs arrive early or late (?)
			case errRstStreamOnInvalidStream:
				fmt.Printf("Ignoring error in session: %s\n", err.Error())
			default:
				s.Close(err)
			}
		}

		s.garbageCollectStreams()
	}
}

func (s *Session) handlePacket(remoteAddr interface{}, publicHeader *PublicHeader, r *bytes.Reader) error {
	// Calcualate packet number
	publicHeader.PacketNumber = calculatePacketNumber(
		publicHeader.PacketNumberLen,
		s.lastRcvdPacketNumber,
		publicHeader.PacketNumber,
	)
	s.lastRcvdPacketNumber = publicHeader.PacketNumber
	fmt.Printf("<- Reading packet %d for connection %d\n", publicHeader.PacketNumber, publicHeader.ConnectionID)

	// TODO: Only do this after authenticating
	s.conn.setCurrentRemoteAddr(remoteAddr)

	packet, err := s.unpacker.Unpack(publicHeader.Raw, publicHeader, r)
	if err != nil {
		return err
	}

	s.receivedPacketHandler.ReceivedPacket(publicHeader.PacketNumber, packet.entropyBit)

	for _, ff := range packet.frames {
		var err error
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			err = s.sentPacketHandler.ReceivedAck(frame)
			// ToDo: send right error in ConnectionClose frame
		case *frames.ConnectionCloseFrame:
			fmt.Printf("%#v\n", frame)
		case *frames.StopWaitingFrame:
			err = s.receivedPacketHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *frames.WindowUpdateFrame:
			fmt.Printf("%#v\n", frame)
		default:
			panic("unexpected frame type")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(remoteAddr interface{}, publicHeader *PublicHeader, r *bytes.Reader) {
	s.receivedPackets <- receivedPacket{remoteAddr: remoteAddr, publicHeader: publicHeader, r: r}
}

// TODO: Ignore data for closed streams
func (s *Session) handleStreamFrame(frame *frames.StreamFrame) error {
	fmt.Printf("Got %d bytes for stream %d\n", len(frame.Data), frame.StreamID)
	if frame.StreamID == 0 {
		return errors.New("Session: 0 is not a valid Stream ID")
	}
	s.streamsMutex.RLock()
	str, streamExists := s.streams[frame.StreamID]
	s.streamsMutex.RUnlock()

	if !streamExists {
		ss, _ := s.NewStream(frame.StreamID)
		str = ss.(*stream)
	}
	if str == nil {
		return errors.New("Session: reopening streams is not allowed")
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

// Close the connection by sending a ConnectionClose frame
func (s *Session) Close(e error) error {
	s.closeChan <- struct{}{}
	if e == nil {
		e = protocol.NewQuicError(errorcodes.QUIC_PEER_GOING_AWAY, "peer going away")
	}
	fmt.Printf("Closing session with error: %s\n", e.Error())
	errorCode := protocol.ErrorCode(1)
	reasonPhrase := e.Error()
	quicError, ok := e.(*protocol.QuicError)
	if ok {
		errorCode = quicError.ErrorCode
	}
	s.closeStreamsWithError(e)
	// TODO: Don't queue, but send immediately
	_ = frames.ConnectionCloseFrame{
		ErrorCode:    errorCode,
		ReasonPhrase: reasonPhrase,
	}
	return nil
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

func (s *Session) sendPacket() error {
	var controlFrames []frames.Frame
	ack := s.receivedPacketHandler.DequeueAckFrame()
	if ack != nil {
		controlFrames = append(controlFrames, ack)
	}
	packet, err := s.packer.PackPacket(controlFrames)

	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}
	s.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber: packet.number,
		Frames:       packet.frames,
		EntropyBit:   packet.entropyBit,
	})
	fmt.Printf("-> Sending packet %d (%d bytes)\n", packet.number, len(packet.raw))
	err = s.conn.write(packet.raw)
	if err != nil {
		return err
	}
	return nil
}

// QueueFrame queues a frame for sending to the client
func (s *Session) QueueStreamFrame(frame *frames.StreamFrame) error {
	s.packer.AddStreamFrame(*frame)
	return nil
}

// NewStream creates a new stream open for reading and writing
func (s *Session) NewStream(id protocol.StreamID) (utils.Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	stream := newStream(s, id)
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
		// Strictly speaking, this is not thread-safe. However it doesn't matter
		// if the stream is deleted just shortly later, so we don't care.
		if v.finishedReading() {
			s.streams[k] = nil
		}
	}
}
