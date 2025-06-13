package wire

import "github.com/quic-go/quic-go/internal/protocol"

type FrameType uint8

// The constants need to match the ones from the RFC9000
// This allows us to easily convert a FrameType into the corresponding byte.
const (
	PingFrameType        FrameType = 0x1
	AckFrameType         FrameType = 0x2
	AckECNFrameType      FrameType = 0x3
	ResetStreamFrameType FrameType = 0x4
	StopSendingFrameType FrameType = 0x5
	CryptoFrameType      FrameType = 0x6
	NewTokenFrameType    FrameType = 0x7

	// TODO: Do we list the various StreamFrameTypes here?

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

	DatagramNoLengthFrameType   FrameType = 0x30
	DatagramWithLengthFrameType FrameType = 0x31
)

func NewFrameType(typ uint64) (FrameType, bool) {
	if byte(typ)&0xf8 == 0x8 {
		return FrameType(typ), true
	} else {
		switch typ {
		case 0x1:
			return PingFrameType, true
		case 0x2:
			return AckFrameType, true
		case 0x3:
			return AckECNFrameType, true
		case 0x4:
			return ResetStreamFrameType, true
		case 0x5:
			return StopSendingFrameType, true
		case 0x6:
			return CryptoFrameType, true
		case 0x7:
			return NewTokenFrameType, true
		case 0x10:
			return MaxDataFrameType, true
		case 0x11:
			return MaxStreamDataFrameType, true
		case 0x12:
			return BidiMaxStreamsFrameType, true
		case 0x13:
			return UniMaxStreamsFrameType, true
		case 0x14:
			return DataBlockedFrameType, true
		case 0x15:
			return StreamDataBlockedFrameType, true
		case 0x16:
			return BidiStreamBlockedFrameType, true
		case 0x17:
			return UniStreamBlockedFrameType, true
		case 0x18:
			return NewConnectionIDFrameType, true
		case 0x19:
			return RetireConnectionIDFrameType, true
		case 0x1a:
			return PathChallengeFrameType, true
		case 0x1b:
			return PathResponseFrameType, true
		case 0x1c:
			return ConnectionCloseFrameType, true
		case 0x1d:
			return ApplicationCloseFrameType, true
		case 0x1e:
			return HandshakeDoneFrameType, true
		case 0x24:
			return ResetStreamAtFrameType, true
		case 0x30:
			return DatagramNoLengthFrameType, true
		case 0x31:
			return DatagramWithLengthFrameType, true
		default:
			return 0, false
		}
	}
}

func (t FrameType) IsStreamFrameType() bool {
	return byte(t)&0xf8 == 0x8
}

func (t FrameType) isAllowedAtEncLevel(encLevel protocol.EncryptionLevel) bool {
	//nolint:exhaustive
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
