package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type receivedPacket struct {
	addr         *net.UDPAddr
	publicHeader *PublicHeader
	r            *bytes.Reader
}

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, utils.Stream)

// A Session is a QUIC session
type Session struct {
	streamCallback StreamCallback

	connection        *net.UDPConn
	currentRemoteAddr *net.UDPAddr

	streams      map[protocol.StreamID]*stream
	streamsMutex sync.RWMutex

	outgoingAckHandler ackhandler.OutgoingPacketAckHandler
	incomingAckHandler ackhandler.IncomingPacketAckHandler

	unpacker *packetUnpacker
	packer   *packetPacker

	receivedPackets chan receivedPacket
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) PacketHandler {
	session := &Session{
		connection:         conn,
		streamCallback:     streamCallback,
		streams:            make(map[protocol.StreamID]*stream),
		outgoingAckHandler: ackhandler.NewOutgoingPacketAckHandler(),
		incomingAckHandler: ackhandler.NewIncomingPacketAckHandler(),
		receivedPackets:    make(chan receivedPacket),
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
		case p := <-s.receivedPackets:
			err = s.handlePacket(p.addr, p.publicHeader, p.r)
		case <-time.After(sendTimeout):
			err = s.sendPacket()
		}
		if err != nil {
			fmt.Printf("Error in session: %s\n", err.Error())
		}
	}
}

func (s *Session) handlePacket(addr *net.UDPAddr, publicHeader *PublicHeader, r *bytes.Reader) error {
	// TODO: Only do this after authenticating
	if addr != s.currentRemoteAddr {
		s.currentRemoteAddr = addr
	}

	packet, err := s.unpacker.Unpack(publicHeader.Raw, publicHeader, r)
	if err != nil {
		s.Close(err)
		return err
	}

	s.incomingAckHandler.ReceivedPacket(publicHeader.PacketNumber, packet.entropyBit)
	s.QueueFrame(s.incomingAckHandler.DequeueAckFrame())

	for _, ff := range packet.frames {
		var err error
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			err = s.outgoingAckHandler.ReceivedAck(frame)
			// ToDo: send right error in ConnectionClose frame
		case *frames.ConnectionCloseFrame:
			fmt.Printf("%#v\n", frame)
		case *frames.StopWaitingFrame:
			err = s.incomingAckHandler.ReceivedStopWaiting(frame)
		case *frames.RstStreamFrame:
			fmt.Printf("%#v\n", frame)
		case *frames.WindowUpdateFrame:
			fmt.Printf("%#v\n", frame)
		default:
			panic("unexpected frame type")
		}
		if err != nil {
			s.Close(err)
			return err
		}
	}
	return nil
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeader *PublicHeader, r *bytes.Reader) {
	s.receivedPackets <- receivedPacket{addr: addr, publicHeader: publicHeader, r: r}
}

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

// Close closes the connection by sending a ConnectionClose frame
func (s *Session) Close(e error) error {
	errorCode := protocol.ErrorCode(1)
	reasonPhrase := e.Error()
	quicError, ok := e.(*protocol.QuicError)
	if ok {
		errorCode = quicError.ErrorCode
	}
	return s.QueueFrame(&frames.ConnectionCloseFrame{
		ErrorCode:    errorCode,
		ReasonPhrase: reasonPhrase,
	})
}

func (s *Session) sendPacket() error {
	packet, err := s.packer.PackPacket()
	if err != nil {
		return err
	}
	if packet == nil {
		return nil
	}
	s.outgoingAckHandler.SentPacket(&ackhandler.Packet{
		PacketNumber: packet.number,
		Plaintext:    packet.payload,
		EntropyBit:   packet.entropyBit,
	})
	fmt.Printf("-> Sending packet %d (%d bytes)\n", packet.number, len(packet.raw))
	_, err = s.connection.WriteToUDP(packet.raw, s.currentRemoteAddr)
	if err != nil {
		return err
	}
	return nil
}

// QueueFrame queues a frame for sending to the client
func (s *Session) QueueFrame(frame frames.Frame) error {
	s.packer.AddFrame(frame)
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

// closeStream is called by a stream to signal that it was closed remotely
// and has fininshed reading its data.
func (s *Session) closeStream(id protocol.StreamID) {
	s.streamsMutex.Lock()
	s.streams[id] = nil
	s.streamsMutex.Unlock()
}
