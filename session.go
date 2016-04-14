package quic

import (
	"bytes"
	"fmt"
	"net"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Session is a QUIC session
type Session struct {
	ConnectionID protocol.ConnectionID
	ServerConfig *ServerConfig

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	Entropy EntropyAccumulator
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, connectionID protocol.ConnectionID, sCfg *ServerConfig) *Session {
	return &Session{
		Connection:   conn,
		ConnectionID: connectionID,
		ServerConfig: sCfg,
	}
}

// HandlePacket handles a packet
func (s *Session) HandlePacket(addr *net.UDPAddr, publicHeaderBinary []byte, publicHeader *PublicHeader, r *bytes.Reader) error {
	// TODO: Only do this after authenticating
	if addr != s.CurrentRemoteAddr {
		s.CurrentRemoteAddr = addr
	}

	nullAEAD := &crypto.NullAEAD{}
	r, err := nullAEAD.Open(0, publicHeaderBinary, r)
	if err != nil {
		return err
	}

	privateFlag, err := r.ReadByte()
	if err != nil {
		return err
	}
	s.Entropy.Add(publicHeader.PacketNumber, privateFlag&0x01 > 0)

	// TODO: Switch frame type here

	frame, err := ParseStreamFrame(r)
	if err != nil {
		return err
	}

	// TODO: Switch stream here
	if frame.StreamID != 1 {
		panic("streamid not 1")
	}

	messageTag, cryptoData, err := ParseCryptoMessage(frame.Data)
	if err != nil {
		panic(err)
	}

	// TODO: Switch client messages here
	if messageTag != TagCHLO {
		panic("expected CHLO")
	}

	if _, ok := cryptoData[TagPUBS]; ok {
		panic("received CHLO with PUBS")
	}

	proof, err := s.ServerConfig.Sign(frame.Data)
	if err != nil {
		return err
	}
	var serverReply bytes.Buffer
	WriteCryptoMessage(&serverReply, TagREJ, map[Tag][]byte{
		TagSCFG: s.ServerConfig.Get(),
		TagCERT: s.ServerConfig.GetCertData(),
		TagPROF: proof,
	})

	s.SendFrames([]Frame{
		&AckFrame{
			Entropy:         s.Entropy.Get(),
			LargestObserved: 1,
		},
		&StreamFrame{
			StreamID: 1,
			Data:     serverReply.Bytes(),
		},
	})

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

	var fullReply bytes.Buffer
	responsePublicHeader := PublicHeader{ConnectionID: s.ConnectionID, PacketNumber: 1}
	fmt.Printf("%#v\n", responsePublicHeader)
	if err := responsePublicHeader.WritePublicHeader(&fullReply); err != nil {
		return err
	}

	(&crypto.NullAEAD{}).Seal(0, &fullReply, fullReply.Bytes(), framesData.Bytes())

	_, err := s.Connection.WriteToUDP(fullReply.Bytes(), s.CurrentRemoteAddr)
	return err
}
