package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

type receivedPacket struct {
	addr         *net.UDPAddr
	publicHeader *PublicHeader
	r            *bytes.Reader
}

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, *Stream)

// A Session is a QUIC session
type Session struct {
	streamCallback StreamCallback

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	Streams map[protocol.StreamID]*Stream

	outgoingAckHandler ackhandler.OutgoingPacketAckHandler
	incomingAckHandler ackhandler.IncomingPacketAckHandler

	unpacker  *packetUnpacker
	packer    *packetPacker
	batchMode bool

	receivedPackets chan receivedPacket
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) PacketHandler {
	session := &Session{
		Connection:         conn,
		streamCallback:     streamCallback,
		Streams:            make(map[protocol.StreamID]*Stream),
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
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
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
	stream, newStream := s.Streams[frame.StreamID]

	if !newStream {
		stream, _ = s.NewStream(frame.StreamID)
	}
	err := stream.AddStreamFrame(frame)
	if err != nil {
		return err
	}
	if !newStream {
		s.streamCallback(s, stream)
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
	s.batchMode = false
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
	_, err = s.Connection.WriteToUDP(packet.raw, s.CurrentRemoteAddr)
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

// NewStream creates a new strean open for reading and writing
func (s *Session) NewStream(id protocol.StreamID) (*Stream, error) {
	stream := NewStream(s, id)
	if s.Streams[id] != nil {
		return nil, fmt.Errorf("Session: stream with ID %d already exists", id)
	}
	s.Streams[id] = stream
	return stream, nil
}
