package quic

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// StreamCallback gets a stream frame and returns a reply frame
type StreamCallback func(*Session, *Stream)

// A Session is a QUIC session
type Session struct {
	VersionNumber protocol.VersionNumber
	ConnectionID  protocol.ConnectionID

	Connection        *net.UDPConn
	CurrentRemoteAddr *net.UDPAddr

	ServerConfig *handshake.ServerConfig
	cryptoSetup  *handshake.CryptoSetup

	EntropyReceived     EntropyAccumulator
	EntropySent         EntropyAccumulator
	EntropyHistory      map[protocol.PacketNumber]EntropyAccumulator // ToDo: store this with the packet itself
	entropyHistoryMutex sync.Mutex

	lastSentPacketNumber     protocol.PacketNumber
	lastObservedPacketNumber protocol.PacketNumber

	Streams      map[protocol.StreamID]*Stream
	streamsMutex sync.RWMutex

	streamCallback StreamCallback
}

// NewSession makes a new session
func NewSession(conn *net.UDPConn, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback) *Session {
	session := &Session{
		Connection:               conn,
		VersionNumber:            v,
		ConnectionID:             connectionID,
		ServerConfig:             sCfg,
		streamCallback:           streamCallback,
		lastObservedPacketNumber: 0,
		Streams:                  make(map[protocol.StreamID]*Stream),
		EntropyHistory:           make(map[protocol.PacketNumber]EntropyAccumulator),
	}

	cryptoStream, _ := session.NewStream(1)
	session.cryptoSetup = handshake.NewCryptoSetup(connectionID, v, sCfg, cryptoStream)
	go session.cryptoSetup.HandleCryptoStream()

	return session
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
	s.EntropyReceived.Add(publicHeader.PacketNumber, privateFlag&0x01 > 0)

	s.SendFrame(&frames.AckFrame{
		LargestObserved: publicHeader.PacketNumber,
		Entropy:         s.EntropyReceived.Get(),
	})

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

	s.entropyHistoryMutex.Lock()
	defer s.entropyHistoryMutex.Unlock()
	expectedEntropy, ok := s.EntropyHistory[frame.LargestObserved]
	if !ok {
		return errors.New("No entropy value saved for received ACK packet")
	}
	delete(s.EntropyHistory, frame.LargestObserved)

	if byte(expectedEntropy) != frame.Entropy {
		return errors.New("Incorrect entropy value in ACK package")
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

// SendFrame sends a frame to the client
func (s *Session) SendFrame(frame frames.Frame) error {
	streamframe, ok := frame.(*frames.StreamFrame)
	if ok {
		maxlength := 1000
		if len(streamframe.Data) > maxlength {
			frame1 := &frames.StreamFrame{
				StreamID: streamframe.StreamID,
				Offset:   streamframe.Offset,
				Data:     streamframe.Data[:maxlength],
			}
			frame2 := &frames.StreamFrame{
				StreamID: streamframe.StreamID,
				Offset:   streamframe.Offset + uint64(maxlength),
				Data:     streamframe.Data[maxlength:],
				FinBit:   streamframe.FinBit,
			}
			err := s.SendFrame(frame1)
			if err != nil {
				return err
			}
			return s.SendFrame(frame2)
		}
	}

	var framesData bytes.Buffer
	entropyBit, err := utils.RandomBit()
	if err != nil {
		return err
	}
	if entropyBit {
		framesData.WriteByte(1)
	} else {
		framesData.WriteByte(0)
	}

	if err := frame.Write(&framesData); err != nil {
		return err
	}

	s.lastSentPacketNumber++

	var fullReply bytes.Buffer
	packetNumber := s.lastSentPacketNumber
	responsePublicHeader := PublicHeader{ConnectionID: s.ConnectionID, PacketNumber: packetNumber}
	if err := responsePublicHeader.WritePublicHeader(&fullReply); err != nil {
		return err
	}
	s.EntropySent.Add(packetNumber, entropyBit)
	s.entropyHistoryMutex.Lock()
	defer s.entropyHistoryMutex.Unlock()
	s.EntropyHistory[packetNumber] = s.EntropySent

	ciphertext := s.cryptoSetup.Seal(s.lastSentPacketNumber, fullReply.Bytes(), framesData.Bytes())
	fullReply.Write(ciphertext)

	fmt.Printf("-> Sending packet %d (%d bytes) to %v\n", responsePublicHeader.PacketNumber, len(fullReply.Bytes()), s.CurrentRemoteAddr)
	_, err = s.Connection.WriteToUDP(fullReply.Bytes(), s.CurrentRemoteAddr)
	return err
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
