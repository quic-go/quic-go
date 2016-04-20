package quic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/errorcodes"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, *Stream)

// A Session is a QUIC session
type Session struct {
	VersionNumber protocol.VersionNumber
	ConnectionID  protocol.ConnectionID

	streamCallback StreamCallback

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	ServerConfig *handshake.ServerConfig
	cryptoSetup  *handshake.CryptoSetup

	Streams      map[protocol.StreamID]*Stream
	streamsMutex sync.RWMutex

	outgoingAckHandler ackhandler.OutgoingPacketAckHandler
	incomingAckHandler ackhandler.IncomingPacketAckHandler

	packer    *packetPacker
	batchMode bool
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) *Session {
	session := &Session{
		Connection:     conn,
		VersionNumber:  v,
		ConnectionID:   connectionID,
		ServerConfig:   sCfg,
		streamCallback: streamCallback,
		Streams:        make(map[protocol.StreamID]*Stream),
	}

	cryptoStream, _ := session.NewStream(1)
	session.cryptoSetup = handshake.NewCryptoSetup(connectionID, v, sCfg, cryptoStream)
	go session.cryptoSetup.HandleCryptoStream()

	session.packer = &packetPacker{aead: session.cryptoSetup}

	return session
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	// TODO: Only do this after authenticating
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
	}

	ciphertext, _ := ioutil.ReadAll(r)
	plaintext, err := s.cryptoSetup.Open(publicHeader.PacketNumber, publicHeaderBinary, ciphertext)
	if err != nil {
		return err
	}
	r = bytes.NewReader(plaintext)

	privateFlag, err := r.ReadByte()
	if err != nil {
		return err
	}

	s.incomingAckHandler.ReceivedPacket(publicHeader.PacketNumber, privateFlag&0x01 > 0)

	s.batchMode = true
	s.SendFrame(s.incomingAckHandler.DequeueAckFrame())

	// read all frames in the packet
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		r.UnreadByte()

		err = nil
		if typeByte&0x80 == 0x80 {
			err = s.handleStreamFrame(r)
		} else if typeByte&0xca == 0x40 {
			err = s.handleAckFrame(r)
		} else if typeByte&0xe0 == 0x20 {
			err = errors.New("unimplemented: CONGESTION_FEEDBACK")
		} else {
			switch typeByte {
			case 0x0: // PAD
				return nil
			case 0x01:
				err = s.handleRstStreamFrame(r)
			case 0x02:
				err = s.handleConnectionCloseFrame(r)
			case 0x03:
				err = errors.New("unimplemented: GOAWAY")
			case 0x04:
				// err = errors.New("unimplemented: WINDOW_UPDATE")
				fmt.Println("unimplemented: WINDOW_UPDATE")
				p := make([]byte, 1+4+8)
				_, err = r.Read(p)
			case 0x05:
				// err = errors.New("unimplemented: BLOCKED")
				fmt.Println("unimplemented: BLOCKED")
				p := make([]byte, 1+4)
				_, err = r.Read(p)
			case 0x06:
				err = s.handleStopWaitingFrame(r, publicHeader)
			case 0x07:
				// PING, do nothing
				r.ReadByte()
			default:
				err = protocol.NewQuicError(errorcodes.QUIC_INVALID_FRAME_DATA, fmt.Sprintf("unknown type byte 0x%x", typeByte))
			}
			if err != nil {
				s.Close(err)
				return err
			}
		}
	}

	s.batchMode = false
	return s.sendPackets()
}

func (s *Session) handleStreamFrame(r *bytes.Reader) error {
	frame, err := frames.ParseStreamFrame(r)
	if err != nil {
		return err
	}
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
	err = stream.AddStreamFrame(frame)
	if err != nil {
		return err
	}
	if !newStream {
		s.streamCallback(s, stream)
	}
	return nil
}

func (s *Session) handleAckFrame(r *bytes.Reader) error {
	frame, err := frames.ParseAckFrame(r)
	if err != nil {
		return err
	}
	s.outgoingAckHandler.ReceivedAck(frame)
	return nil
}

func (s *Session) handleConnectionCloseFrame(r *bytes.Reader) error {
	fmt.Println("Detected CONNECTION_CLOSE")
	frame, err := frames.ParseConnectionCloseFrame(r)
	if err != nil {
		return err
	}
	fmt.Printf("%#v\n", frame)
	return nil
}

func (s *Session) handleStopWaitingFrame(r *bytes.Reader, publicHeader *PublicHeader) error {
	frame, err := frames.ParseStopWaitingFrame(r, publicHeader.PacketNumberLen)
	if err != nil {
		return err
	}
	fmt.Printf("%#v\n", frame)
	return nil
}

func (s *Session) handleRstStreamFrame(r *bytes.Reader) error {
	frame, err := frames.ParseRstStreamFrame(r)
	if err != nil {
		return err
	}
	fmt.Printf("%#v\n", frame)
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
