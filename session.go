package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Stream) []frames.Frame

// A Session is a QUIC session
type Session struct {
	VersionNumber protocol.VersionNumber
	ConnectionID  protocol.ConnectionID

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	ServerConfig *handshake.ServerConfig
	cryptoSetup  *handshake.CryptoSetup

	Entropy EntropyAccumulator

	lastSentPacketNumber     protocol.PacketNumber
	lastObservedPacketNumber protocol.PacketNumber

	Streams map[protocol.StreamID]*Stream

	streamCallback StreamCallback

	s1offset uint64
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) *Session {
	return &Session{
		Connection:               conn,
		VersionNumber:            v,
		ConnectionID:             connectionID,
		ServerConfig:             sCfg,
		cryptoSetup:              handshake.NewCryptoSetup(connectionID, v, sCfg),
		streamCallback:           streamCallback,
		lastObservedPacketNumber: 0,
		Streams:                  make(map[protocol.StreamID]*Stream),
	}
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	if s.lastObservedPacketNumber > 0 { // the first packet doesn't neccessarily need to have packetNumber 1
		if publicHeader.PacketNumber < s.lastObservedPacketNumber || publicHeader.PacketNumber > s.lastObservedPacketNumber+1 {
			return errors.New("Out of order packet")
		}
		if publicHeader.PacketNumber == s.lastObservedPacketNumber {
			return errors.New("Duplicate packet")
		}
	}
	s.lastObservedPacketNumber = publicHeader.PacketNumber

	// TODO: Only do this after authenticating
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
	}

	r, err := s.cryptoSetup.Open(publicHeader.PacketNumber, publicHeaderBinary, r)
	if err != nil {
		return err
	}

	privateFlag, err := r.ReadByte()
	if err != nil {
		return err
	}
	s.Entropy.Add(publicHeader.PacketNumber, privateFlag&0x01 > 0)

	s.SendFrames([]frames.Frame{&frames.AckFrame{
		LargestObserved: uint64(publicHeader.PacketNumber),
		Entropy:         s.Entropy.Get(),
	}})

	// read all frames in the packet
	for r.Len() > 0 {
		typeByte, _ := r.ReadByte()
		r.UnreadByte()

		err = nil
		if typeByte&0x80 == 0x80 {
			err = s.handleStreamFrame(r)
		} else if typeByte == 0x40 {
			err = s.handleAckFrame(r)
		} else if typeByte&0xE0 == 0x20 {
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
				err = errors.New("unimplemented: WINDOW_UPDATE")
			case 0x05:
				err = errors.New("unimplemented: BLOCKED")
			case 0x06:
				err = s.handleStopWaitingFrame(r, publicHeader)
			case 0x07:
				// PING, do nothing
				r.ReadByte()
			default:
				err = fmt.Errorf("unknown frame type: %x", typeByte)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
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

	if frame.StreamID == 1 {
		reply, err := s.cryptoSetup.HandleCryptoMessage(frame.Data)
		if err != nil {
			return err
		}
		if reply != nil {
			if len(reply) > 1000 {
				s.SendFrames([]frames.Frame{&frames.StreamFrame{StreamID: 1, Offset: s.s1offset, Data: reply[:1000]}})
				s.s1offset += 1000
				s.SendFrames([]frames.Frame{&frames.StreamFrame{StreamID: 1, Offset: s.s1offset, Data: reply[1000:]}})
				s.s1offset += uint64(len(reply[1000:]))
			} else {
				s.SendFrames([]frames.Frame{&frames.StreamFrame{StreamID: 1, Offset: s.s1offset, Data: reply}})
				s.s1offset += uint64(len(reply))
			}
		}
	} else {
		stream, ok := s.Streams[frame.StreamID]
		if !ok {
			stream = NewStream(frame.StreamID)
			s.Streams[frame.StreamID] = stream
		}
		err := stream.AddStreamFrame(frame)
		if err != nil {
			return err
		}

		replyFrames := s.streamCallback(stream)
		if replyFrames != nil {
			s.SendFrames(replyFrames)
		}
	}
	return nil
}

func (s *Session) handleAckFrame(r *bytes.Reader) error {
	_, err := frames.ParseAckFrame(r)
	if err != nil {
		return err
	}
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
	_, err := frames.ParseStopWaitingFrame(r, publicHeader.PacketNumberLen)
	if err != nil {
		return err
	}
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

// SendFrames sends a number of frames to the client
func (s *Session) SendFrames(frames []frames.Frame) error {
	var framesData bytes.Buffer
	framesData.WriteByte(0) // TODO: entropy
	for _, f := range frames {
		if err := f.Write(&framesData); err != nil {
			return err
		}
	}

	s.lastSentPacketNumber++

	var fullReply bytes.Buffer
	responsePublicHeader := PublicHeader{ConnectionID: s.ConnectionID, PacketNumber: s.lastSentPacketNumber}
	if err := responsePublicHeader.WritePublicHeader(&fullReply); err != nil {
		return err
	}

	s.cryptoSetup.Seal(s.lastSentPacketNumber, &fullReply, fullReply.Bytes(), framesData.Bytes())

	fmt.Printf("-> Sending packet %d (%d bytes) to %v\n", responsePublicHeader.PacketNumber, len(fullReply.Bytes()), s.CurrentRemoteAddr)
	_, err := s.Connection.WriteToUDP(fullReply.Bytes(), s.CurrentRemoteAddr)
	return err
}
