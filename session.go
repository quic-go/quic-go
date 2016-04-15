package quic

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*StreamFrame) []Frame

// A Session is a QUIC session
type Session struct {
	VersionNumber protocol.VersionNumber
	ConnectionID  protocol.ConnectionID
	ServerConfig  *ServerConfig

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	aead crypto.AEAD

	Entropy EntropyAccumulator

	lastSentPacketNumber protocol.PacketNumber

	streamCallback StreamCallback
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *ServerConfig, streamCallback StreamCallback) *Session {
	return &Session{
		Connection:     conn,
		VersionNumber:  v,
		ConnectionID:   connectionID,
		ServerConfig:   sCfg,
		aead:           &crypto.NullAEAD{},
		streamCallback: streamCallback,
	}
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	// TODO: Only do this after authenticating
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
	}

	r, err := s.aead.Open(publicHeader.PacketNumber, publicHeaderBinary, r)
	if err != nil {
		return err
	}

	privateFlag, err := r.ReadByte()
	if err != nil {
		return err
	}
	s.Entropy.Add(publicHeader.PacketNumber, privateFlag&0x01 > 0)

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
			frame, err := ParseStreamFrame(r)
			if err != nil {
				return err
			}
			fmt.Printf("Got %d bytes for stream %d\n", len(frame.Data), frame.StreamID)

			if frame.StreamID == 0 {
				return errors.New("Session: 0 is not a valid Stream ID")
			}

			if frame.StreamID == 1 {
				s.HandleCryptoHandshake(frame)
			} else {
				replyFrames := s.streamCallback(frame)
				s.SendFrames(append([]Frame{&AckFrame{Entropy: s.Entropy.Get(), LargestObserved: 3}}, replyFrames...))
			}
			continue
		} else if typeByte&0xC0 == 0x40 { // ACK
			fmt.Println("Detected ACK")
			frame, err := ParseAckFrame(r)
			if err != nil {
				return err
			}

			fmt.Printf("%#v\n", frame)

			continue
		} else if typeByte&0xE0 == 0x20 { // CONGESTION_FEEDBACK
			return errors.New("Detected CONGESTION_FEEDBACK")
		} else if typeByte&0x06 == 0x06 { // STOP_WAITING
			fmt.Println("Detected STOP_WAITING")
			_, err := ParseStopWaitingFrame(r, publicHeader.PacketNumberLen)
			if err != nil {
				return err
			}
			// ToDo: react to receiving this frame
		} else if typeByte&0x02 == 0x02 { // CONNECTION_CLOSE
			fmt.Println("Detected CONNECTION_CLOSE")
			frame, err := ParseConnectionCloseFrame(r)
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
func (s *Session) SendFrames(frames []Frame) error {
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

	s.aead.Seal(s.lastSentPacketNumber, &fullReply, fullReply.Bytes(), framesData.Bytes())

	_, err := s.Connection.WriteToUDP(fullReply.Bytes(), s.CurrentRemoteAddr)
	return err
}

// HandleCryptoHandshake handles the crypto handshake
func (s *Session) HandleCryptoHandshake(frame *StreamFrame) error {
	messageTag, cryptoData, err := handshake.ParseHandshakeMessage(frame.Data)
	if err != nil {
		panic(err)
	}

	// TODO: Switch client messages here
	if messageTag != handshake.TagCHLO {
		return errors.New("Session: expected CHLO")
	}

	if _, ok := cryptoData[handshake.TagSCID]; ok {
		var sharedSecret []byte
		sharedSecret, err = s.ServerConfig.kex.CalculateSharedKey(cryptoData[handshake.TagPUBS])
		if err != nil {
			return err
		}
		s.aead, err = crypto.DeriveKeysChacha20(sharedSecret, cryptoData[handshake.TagNONC], s.ConnectionID, frame.Data, s.ServerConfig.Get(), s.ServerConfig.kd.GetCertUncompressed())
		if err != nil {
			return err
		}
		s.SendFrames([]Frame{&AckFrame{
			Entropy:         s.Entropy.Get(),
			LargestObserved: 2,
		}})
		return nil
	}

	var chloOrNil []byte
	if s.VersionNumber > protocol.VersionNumber(30) {
		chloOrNil = frame.Data
	}
	proof, err := s.ServerConfig.Sign(chloOrNil)
	if err != nil {
		return err
	}
	var serverReply bytes.Buffer
	handshake.WriteHandshakeMessage(&serverReply, handshake.TagREJ, map[handshake.Tag][]byte{
		handshake.TagSCFG: s.ServerConfig.Get(),
		handshake.TagCERT: s.ServerConfig.GetCertCompressed(),
		handshake.TagPROF: proof,
	})

	return s.SendFrames([]Frame{
		&AckFrame{
			Entropy:         s.Entropy.Get(),
			LargestObserved: 1,
		},
		&StreamFrame{
			StreamID: 1,
			Data:     serverReply.Bytes(),
		},
	})
}
