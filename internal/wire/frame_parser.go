package wire

import (
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"
)

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

var errUnknownFrameType = errors.New("unknown frame type")

// The FrameParser parses QUIC frames, one by one.
type FrameParser struct {
	ackDelayExponent      uint8
	supportsDatagrams     bool
	supportsResetStreamAt bool

	// To avoid allocating when parsing, keep a single ACK frame struct.
	// It is used over and over again.
	ackFrame *AckFrame
}

// NewFrameParser creates a new frame parser.
func NewFrameParser(supportsDatagrams, supportsResetStreamAt bool) *FrameParser {
	return &FrameParser{
		supportsDatagrams:     supportsDatagrams,
		supportsResetStreamAt: supportsResetStreamAt,
		ackFrame:              &AckFrame{},
	}
}

func (p *FrameParser) ParseTyp(b []byte) (FrameType, int, error) {
	var parsed int
	for len(b) != 0 {
		typ, l, err := quicvarint.Parse(b)
		parsed += l
		if err != nil {
			return 0, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		b = b[l:]
		if typ == 0x0 { // skip PADDING frames
			continue
		}
		return FrameType(typ), parsed, nil
	}
	return 0, parsed, nil
}

// ParseNext parses the next frame.
// It skips PADDING frames.
func (p *FrameParser) ParseNext(data []byte, encLevel protocol.EncryptionLevel, v protocol.Version) (int, Frame, error) {
	frame, l, err := p.parseNext(data, encLevel, v)
	return l, frame, err
}

func (p *FrameParser) parseNext(b []byte, encLevel protocol.EncryptionLevel, v protocol.Version) (Frame, int, error) {
	var parsed int
	for len(b) != 0 {
		typ, l, err := quicvarint.Parse(b)
		parsed += l
		if err != nil {
			return nil, parsed, &qerr.TransportError{
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		b = b[l:]
		if typ == 0x0 { // skip PADDING frames
			continue
		}

		f, l, err := p.parseFrame(b, typ, encLevel, v)
		parsed += l
		if err != nil {
			return nil, parsed, &qerr.TransportError{
				FrameType:    typ,
				ErrorCode:    qerr.FrameEncodingError,
				ErrorMessage: err.Error(),
			}
		}
		return f, parsed, nil
	}
	return nil, parsed, nil
}

func (p *FrameParser) parseFrame(b []byte, typ uint64, encLevel protocol.EncryptionLevel, v protocol.Version) (Frame, int, error) {
	var frame Frame
	var err error
	var l int
	if typ&0xf8 == 0x8 {
		frame, l, err = parseStreamFrame(b, typ, v)
	} else {
		frameTyp := FrameType(typ)
		switch frameTyp {
		case PingFrameType:
			frame = &PingFrame{}
		case AckFrameType, AckECNFrameType:
			ackDelayExponent := p.ackDelayExponent
			if encLevel != protocol.Encryption1RTT {
				ackDelayExponent = protocol.DefaultAckDelayExponent
			}
			p.ackFrame.Reset()
			l, err = ParseAckFrame(p.ackFrame, b, frameTyp, ackDelayExponent, v)
			frame = p.ackFrame
		case ResetStreamFrameType:
			frame, l, err = ParseResetStreamFrame(b, false, v)
		case StopSendingFrameType:
			frame, l, err = ParseStopSendingFrame(b, v)
		case CryptoFrameType:
			frame, l, err = ParseCryptoFrame(b, v)
		case NewTokenFrameType:
			frame, l, err = ParseNewTokenFrame(b, v)
		case MaxDataFrameType:
			frame, l, err = ParseMaxDataFrame(b, v)
		case MaxStreamDataFrameType:
			frame, l, err = ParseMaxStreamDataFrame(b, v)
		case BidiMaxStreamsFrameType, UniMaxStreamsFrameType:
			frame, l, err = ParseMaxStreamsFrame(b, frameTyp, v)
		case DataBlockedFrameType:
			frame, l, err = ParseDataBlockedFrame(b, v)
		case StreamDataBlockedFrameType:
			frame, l, err = ParseStreamDataBlockedFrame(b, v)
		case BidiStreamBlockedFrameType, UniStreamBlockedFrameType:
			frame, l, err = ParseStreamsBlockedFrame(b, frameTyp, v)
		case NewConnectionIDFrameType:
			frame, l, err = ParseNewConnectionIDFrame(b, v)
		case RetireConnectionIDFrameType:
			frame, l, err = ParseRetireConnectionIDFrame(b, v)
		case PathChallengeFrameType:
			frame, l, err = ParsePathChallengeFrame(b, v)
		case PathResponseFrameType:
			frame, l, err = ParsePathResponseFrame(b, v)
		case ConnectionCloseFrameType, ApplicationCloseFrameType:
			frame, l, err = ParseConnectionCloseFrame(b, frameTyp, v)
		case HandshakeDoneFrameType:
			frame = &HandshakeDoneFrame{}
		case 0x30, 0x31:
			if !p.supportsDatagrams {
				return nil, 0, errUnknownFrameType
			}
			frame, l, err = ParseDatagramFrame(b, typ, v)
		case ResetStreamAtFrameType:
			if !p.supportsResetStreamAt {
				return nil, 0, errUnknownFrameType
			}
			frame, l, err = ParseResetStreamFrame(b, true, v)
		default:
			err = errUnknownFrameType
		}
	}
	if err != nil {
		return nil, 0, err
	}
	if !p.isAllowedAtEncLevel(frame, encLevel) {
		return nil, l, fmt.Errorf("%s not allowed at encryption level %s", reflect.TypeOf(frame).Elem().Name(), encLevel)
	}
	return frame, l, nil
}

func (p *FrameParser) isAllowedAtEncLevel(f Frame, encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial, protocol.EncryptionHandshake:
		switch f.(type) {
		case *CryptoFrame, *AckFrame, *ConnectionCloseFrame, *PingFrame:
			return true
		default:
			return false
		}
	case protocol.Encryption0RTT:
		switch f.(type) {
		case *CryptoFrame, *AckFrame, *ConnectionCloseFrame, *NewTokenFrame, *PathResponseFrame, *RetireConnectionIDFrame:
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

// SetAckDelayExponent sets the acknowledgment delay exponent (sent in the transport parameters).
// This value is used to scale the ACK Delay field in the ACK frame.
func (p *FrameParser) SetAckDelayExponent(exp uint8) {
	p.ackDelayExponent = exp
}

func replaceUnexpectedEOF(e error) error {
	if e == io.ErrUnexpectedEOF {
		return io.EOF
	}
	return e
}
