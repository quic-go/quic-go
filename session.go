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

// A Session is a QUIC session
type Session struct {
	ConnectionID protocol.ConnectionID
	ServerConfig *ServerConfig

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	aead crypto.AEAD

	Entropy EntropyAccumulator

	lastSentPacketNumber protocol.PacketNumber
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, connectionID protocol.ConnectionID, sCfg *ServerConfig) *Session {
	return &Session{
		Connection:   conn,
		ConnectionID: connectionID,
		ServerConfig: sCfg,
		aead:         &crypto.NullAEAD{},
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

		frameCounter++
		fmt.Printf("Reading frame %d\n", frameCounter)
		fmt.Printf("\ttype byte: %b\n", typeByte)

		if (typeByte&0x80)>>7 == 1 { // STREAM
			fmt.Println("Detected STREAM")
			frame, err := ParseStreamFrame(r, typeByte)
			if err != nil {
				return err
			}
			fmt.Printf("Got %d bytes for stream %d\n", len(frame.Data), frame.StreamID)

			if frame.StreamID == 0 {
				return errors.New("Session: 0 is not a valid Stream ID")
			}

			// TODO: Switch stream here
			if frame.StreamID == 1 {
				s.HandleCryptoHandshake(frame)
			} else {
				fmt.Printf("%#v\n", frame)
				panic("streamid not 1")
			}

		} else if (typeByte&0xC0)>>6 == 1 { // ACK
			fmt.Println("Detected ACK")
			continue // not yet implemented
		} else if (typeByte&0xE0)>>5 == 1 { // CONGESTION_FEEDBACK
			fmt.Println("Detected CONGESTION_FEEDBACK")
			continue // not yet implemented
		} else {
			fmt.Println("Detected invalid frame type. Not looking for any further frames in this packet.")
			// at least one of the first three bits of the Type field has be 1
			// ToDo: sometimes there are packets that have this kind of "frame". Find out what's going wrong there. Ignore for the moment
			// return errors.New("Session: invalid Frame Type Field")
			break
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

	proof, err := s.ServerConfig.Sign(frame.Data)
	if err != nil {
		return err
	}
	var serverReply bytes.Buffer
	handshake.WriteHandshakeMessage(&serverReply, handshake.TagREJ, map[handshake.Tag][]byte{
		handshake.TagSCFG: s.ServerConfig.Get(),
		handshake.TagCERT: s.ServerConfig.GetCertData(),
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
