package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, *Stream)

// A Session is a QUIC session
type Session struct {
	streamCallback StreamCallback

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	Streams      map[protocol.StreamID]*Stream
	streamsMutex sync.RWMutex

	outgoingAckHandler ackhandler.OutgoingPacketAckHandler
	incomingAckHandler ackhandler.IncomingPacketAckHandler

	unpacker  *packetUnpacker
	packer    *packetPacker
	batchMode bool
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) PacketHandler {
	session := &Session{
		Connection:     conn,
		streamCallback: streamCallback,
		Streams:        make(map[protocol.StreamID]*Stream),
	}

	cryptoStream, _ := session.NewStream(1)
	cryptoSetup := handshake.NewCryptoSetup(connectionID, v, sCfg, cryptoStream)
	go cryptoSetup.HandleCryptoStream()

	session.packer = &packetPacker{aead: cryptoSetup}
	session.unpacker = &packetUnpacker{aead: cryptoSetup}

	return session
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	s.batchMode = true

	// TODO: Only do this after authenticating
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
	}

	packet, err := s.unpacker.Unpack(publicHeaderBinary, publicHeader, r)
	if err != nil {
		s.Close(err)
		return err
	}

	s.incomingAckHandler.ReceivedPacket(publicHeader.PacketNumber, packet.entropyBit)

	s.SendFrame(s.incomingAckHandler.DequeueAckFrame())

	for _, ff := range packet.frames {
		var err error
		switch frame := ff.(type) {
		case *frames.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *frames.AckFrame:
			s.outgoingAckHandler.ReceivedAck(frame)
		case *frames.ConnectionCloseFrame:
			fmt.Printf("%#v\n", frame)
		case *frames.StopWaitingFrame:
			fmt.Printf("%#v\n", frame)
		case *frames.RstStreamFrame:
			fmt.Printf("%#v\n", frame)
		default:
			panic("unexpected frame type")
		}
		if err != nil {
			s.Close(err)
			return err
		}
	}

	s.batchMode = false
	return s.sendPackets()
}

func (s *Session) handleStreamFrame(frame *frames.StreamFrame) error {
	fmt.Printf("Got %d bytes for stream %d\n", len(frame.Data), frame.StreamID)
	if frame.StreamID == 0 {
		return errors.New("Session: 0 is not a valid Stream ID")
	}
	s.streamsMutex.RLock()
	stream, newStream := s.Streams[frame.StreamID]
	s.streamsMutex.RUnlock()

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
	return s.SendFrame(&frames.ConnectionCloseFrame{
		ErrorCode:    errorCode,
		ReasonPhrase: reasonPhrase,
	})
}

func (s *Session) sendPackets() error {
	for {
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
		_, err = s.Connection.WriteToUDP(packet.raw, s.CurrentRemoteAddr)
		if err != nil {
			return err
		}
	}
}

// SendFrame sends a frame to the client
func (s *Session) SendFrame(frame frames.Frame) error {
	s.packer.AddFrame(frame)
	if s.batchMode {
		return nil
	}
	return s.sendPackets()
}

// NewStream creates a new strean open for reading and writing
func (s *Session) NewStream(id protocol.StreamID) (*Stream, error) {
	s.streamsMutex.Lock()
	defer s.streamsMutex.Unlock()
	stream := NewStream(s, id)
	if s.Streams[id] != nil {
		return nil, fmt.Errorf("Session: stream with ID %d already exists", id)
	}
	s.Streams[id] = stream
	return stream, nil
}
