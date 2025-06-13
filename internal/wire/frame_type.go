package wire

import "github.com/quic-go/quic-go/internal/protocol"

type FrameType uint8

const (
	PingFrameType               FrameType = 0x1
	AckFrameType                FrameType = 0x2
	AckECNFrameType             FrameType = 0x3
	ResetStreamFrameType        FrameType = 0x4
	StopSendingFrameType        FrameType = 0x5
	CryptoFrameType             FrameType = 0x6
	NewTokenFrameType           FrameType = 0x7
	MaxDataFrameType            FrameType = 0x10
	MaxStreamDataFrameType      FrameType = 0x11
	BidiMaxStreamsFrameType     FrameType = 0x12
	UniMaxStreamsFrameType      FrameType = 0x13
	DataBlockedFrameType        FrameType = 0x14
	StreamDataBlockedFrameType  FrameType = 0x15
	BidiStreamBlockedFrameType  FrameType = 0x16
	UniStreamBlockedFrameType   FrameType = 0x17
	NewConnectionIDFrameType    FrameType = 0x18
	RetireConnectionIDFrameType FrameType = 0x19
	PathChallengeFrameType      FrameType = 0x1a
	PathResponseFrameType       FrameType = 0x1b
	ConnectionCloseFrameType    FrameType = 0x1c
	ApplicationCloseFrameType   FrameType = 0x1d
	HandshakeDoneFrameType      FrameType = 0x1e
	ResetStreamAtFrameType      FrameType = 0x24 // https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/06/
)

func (t FrameType) IsStreamFrameType() bool {
	return byte(t)&0xf8 == 0x8
}

func (t FrameType) isAllowedAtEncLevel(encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		switch t {
		case CryptoFrameType, AckFrameType, AckECNFrameType, ConnectionCloseFrameType, PingFrameType:
			return true
		default:
			return false
		}
	case protocol.Encryption0RTT:
		switch t {
		case CryptoFrameType, AckFrameType, AckECNFrameType, ConnectionCloseFrameType, NewTokenFrameType, PathResponseFrameType, RetireConnectionIDFrameType:
			return false
		default:
			return true
		}
	case protocol.Encryption1RTT:
		return true
	default:
		panic("unknown encryption level")
	}
}
