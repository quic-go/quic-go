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
type StreamCallback func(*frames.StreamFrame) []frames.Frame

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

	streamCallback StreamCallback
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
	}
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	// TODO: Only do this after authenticating

	if s.lastObservedPacketNumber > 0 { // the first packet doesn't neccessarily need to have packetNumber 1
		if publicHeader.PacketNumber < s.lastObservedPacketNumber || publicHeader.PacketNumber > s.lastObservedPacketNumber+1 {
			return errors.New("Out of order packet")
		}
		if publicHeader.PacketNumber == s.lastObservedPacketNumber {
			return errors.New("Duplicate packet")
		}
	}
	s.lastObservedPacketNumber = publicHeader.PacketNumber

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

	frameCounter := 0

	// read all frames in the packet
	for r.Len() > 0 {
		typeByte, err := r.ReadByte()
		if err != nil {
			fmt.Println("No more frames in this packet.")
			break
		}
		r.UnreadByte()

		frameCounter++
		fmt.Printf("Reading frame %d\n", frameCounter)

		if typeByte&0x80 == 0x80 { // STREAM
			fmt.Println("Detected STREAM")
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
					s.SendFrames([]frames.Frame{&frames.StreamFrame{StreamID: 1, Data: reply}})
				}
			} else {
				replyFrames := s.streamCallback(frame)
				if replyFrames != nil {
					s.SendFrames(replyFrames)
				}
			}
			continue
		} else if typeByte&0xC0 == 0x40 { // ACK
			fmt.Println("Detected ACK")
			frame, err := frames.ParseAckFrame(r)
			if err != nil {
				return err
			}

			fmt.Printf("%#v\n", frame)

			continue
		} else if typeByte&0xE0 == 0x20 { // CONGESTION_FEEDBACK
			return errors.New("Detected CONGESTION_FEEDBACK")
		} else if typeByte&0x06 == 0x06 { // STOP_WAITING
			fmt.Println("Detected STOP_WAITING")
			_, err := frames.ParseStopWaitingFrame(r, publicHeader.PacketNumberLen)
			if err != nil {
				return err
			}
			// ToDo: react to receiving this frame
		} else if typeByte&0x02 == 0x02 { // CONNECTION_CLOSE
			fmt.Println("Detected CONNECTION_CLOSE")
			frame, err := frames.ParseConnectionCloseFrame(r)
			if err != nil {
				return err
			}
			fmt.Printf("%#v\n", frame)
		} else if typeByte == 0 {
			// PAD
			return nil
		} else {
			return errors.New("Session: invalid Frame Type Field")
		}
	}
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
	fmt.Printf("Sending packet # %d\n", responsePublicHeader.PacketNumber)
	if err := responsePublicHeader.WritePublicHeader(&fullReply); err != nil {
		return err
	}

	s.cryptoSetup.Seal(s.lastSentPacketNumber, &fullReply, fullReply.Bytes(), framesData.Bytes())

	fmt.Printf("Sending %d bytes to %v\n", len(fullReply.Bytes()), s.CurrentRemoteAddr)
	_, err := s.Connection.WriteToUDP(fullReply.Bytes(), s.CurrentRemoteAddr)
	return err
}
