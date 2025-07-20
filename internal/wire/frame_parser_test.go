package wire

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
)

func TestFrameTypeParsingReturnsNilWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true, true)
	frameType, l, err := parser.ParseType(nil, protocol.Encryption1RTT)
	require.Equal(t, io.EOF, err)
	require.Zero(t, frameType)
	require.Zero(t, l)
}

func TestParseLessCommonFrameReturnsEOFWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true, true)
	l, f, err := parser.ParseLessCommonFrame(FrameTypeMaxStreamData, nil, protocol.Version1)
	require.IsType(t, &qerr.TransportError{}, err)
	require.Zero(t, l)
	require.Zero(t, f)
}

func TestFrameParsingSkipsPaddingFrames(t *testing.T) {
	parser := NewFrameParser(true, true)
	b := []byte{0, 0} // 2 PADDING frames
	b, err := (&PingFrame{}).Append(b, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, 3, l)
	require.Equal(t, FrameTypePing, frameType)

	frame, l, err := parser.ParseLessCommonFrame(frameType, b[1:], protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.IsType(t, &PingFrame{}, frame)
}

func TestFrameParsingHandlesPaddingAtEnd(t *testing.T) {
	parser := NewFrameParser(true, true)
	b := []byte{0, 0, 0}

	_, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.Equal(t, io.EOF, err)
	require.Equal(t, 3, l)
}

func TestFrameParsingParsesSingleFrame(t *testing.T) {
	parser := NewFrameParser(true, true)
	var b []byte
	for range 10 {
		var err error
		b, err = (&PingFrame{}).Append(b, protocol.Version1)
		require.NoError(t, err)
	}
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypePing, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseLessCommonFrame(frameType, b, protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.IsType(t, &PingFrame{}, frame)
}

func TestFrameParserACK(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAck, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseAckFrame(frameType, b[l:], protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.Equal(t, protocol.PacketNumber(0x13), frame.LargestAcked())
	require.Equal(t, len(b)-1, l)
}

func TestFrameParserAckDelay(t *testing.T) {
	t.Run("1-RTT", func(t *testing.T) {
		testFrameParserAckDelay(t, protocol.Encryption1RTT)
	})
	t.Run("Handshake", func(t *testing.T) {
		testFrameParserAckDelay(t, protocol.EncryptionHandshake)
	})
}

func testFrameParserAckDelay(t *testing.T, encLevel protocol.EncryptionLevel) {
	parser := NewFrameParser(true, true)
	parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: time.Second,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, encLevel)
	require.NoError(t, err)
	require.Equal(t, FrameTypeAck, frameType)
	require.Equal(t, 1, l)

	frame, l, err := parser.ParseAckFrame(frameType, b[l:], encLevel, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(b)-1, l)
	if encLevel == protocol.Encryption1RTT {
		require.Equal(t, 4*time.Second, frame.DelayTime)
	} else {
		require.Equal(t, time.Second, frame.DelayTime)
	}
}

func checkFrameUnsupported(t *testing.T, err error, expectedFrameType uint64) {
	t.Helper()
	require.ErrorContains(t, err, errUnknownFrameType.Error())
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, expectedFrameType, transportErr.FrameType)
	require.Equal(t, "unknown frame type", transportErr.ErrorMessage)
}

func TestFrameParserStreamFrames(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &StreamFrame{
		StreamID: 0x42,
		Offset:   0x1337,
		Fin:      true,
		Data:     []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameType(0xd), frameType)
	require.True(t, frameType.IsStreamFrameType())
	require.Equal(t, 1, l)

	// ParseLessCommonFrame should not handle Stream Frames
	frame, l, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	checkFrameUnsupported(t, err, 0xd)
	require.Nil(t, frame)
	require.Zero(t, l)
}

func TestParseStreamFrameWrapsError(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &StreamFrame{
		StreamID:       0x1234,
		Offset:         0x1000,
		Data:           []byte("hello world"),
		DataLenPresent: true,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	// Corrupt the buffer to trigger a parse error
	b = b[:len(b)-2] // Remove last 2 bytes to cause an EOF

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)

	frame, n, err := parser.ParseStreamFrame(frameType, b[l:], protocol.Version1)
	require.Nil(t, frame)
	require.Zero(t, n)

	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, uint64(frameType), transportErr.FrameType)
	require.Contains(t, transportErr.Error(), "EOF")
}

func TestParseStreamFrameSuccess(t *testing.T) {
	parser := NewFrameParser(true, true)
	original := &StreamFrame{
		StreamID:       0x1234,
		Offset:         0x1000,
		Fin:            true,
		Data:           []byte("hello world"),
		DataLenPresent: true,
	}
	b, err := original.Append(nil, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.True(t, frameType.IsStreamFrameType())
	require.Equal(t, FrameType(0x0f), frameType) // STREAM | OFF | LEN | FIN

	parsed, n, err := parser.ParseStreamFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, len(b)-l, n)

	require.Equal(t, original.StreamID, parsed.StreamID)
	require.Equal(t, original.Offset, parsed.Offset)
	require.Equal(t, original.Fin, parsed.Fin)
	require.Equal(t, original.DataLenPresent, parsed.DataLenPresent)
	require.Equal(t, original.Data, parsed.Data)
}

func TestFrameParserFrames(t *testing.T) {
	tests := []struct {
		name      string
		frameType FrameType
		frame     Frame
	}{
		{
			name:      "MAX_DATA",
			frameType: FrameTypeMaxData,
			frame:     &MaxDataFrame{MaximumData: 0xcafe},
		},
		{
			name:      "MAX_STREAM_DATA",
			frameType: FrameTypeMaxStreamData,
			frame:     &MaxStreamDataFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdecafbad},
		},
		{
			name:      "RESET_STREAM",
			frameType: FrameTypeResetStream,
			frame: &ResetStreamFrame{
				StreamID:  0xdeadbeef,
				FinalSize: 0xdecafbad1234,
				ErrorCode: 0x1337,
			},
		},
		{
			name:      "STOP_SENDING",
			frameType: FrameTypeStopSending,
			frame:     &StopSendingFrame{StreamID: 0x42},
		},
		{
			name:      "CRYPTO",
			frameType: FrameTypeCrypto,
			frame:     &CryptoFrame{Offset: 0x1337, Data: []byte("lorem ipsum")},
		},
		{
			name:      "NEW_TOKEN",
			frameType: FrameTypeNewToken,
			frame:     &NewTokenFrame{Token: []byte("foobar")},
		},
		{
			name:      "MAX_STREAMS",
			frameType: FrameTypeBidiMaxStreams,
			frame:     &MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 0x1337},
		},
		{
			name:      "DATA_BLOCKED",
			frameType: FrameTypeDataBlocked,
			frame:     &DataBlockedFrame{MaximumData: 0x1234},
		},
		{
			name:      "STREAM_DATA_BLOCKED",
			frameType: FrameTypeStreamDataBlocked,
			frame:     &StreamDataBlockedFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdead},
		},
		{
			name:      "STREAMS_BLOCKED",
			frameType: FrameTypeBidiStreamBlocked,
			frame:     &StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 0x1234567},
		},
		{
			name:      "NEW_CONNECTION_ID",
			frameType: FrameTypeNewConnectionID,
			frame: &NewConnectionIDFrame{
				SequenceNumber:      0x1337,
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			},
		},
		{
			name:      "RETIRE_CONNECTION_ID",
			frameType: FrameTypeRetireConnectionID,
			frame:     &RetireConnectionIDFrame{SequenceNumber: 0x1337},
		},
		{
			name:      "PATH_CHALLENGE",
			frameType: FrameTypePathChallenge,
			frame:     &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:      "PATH_RESPONSE",
			frameType: FrameTypePathResponse,
			frame:     &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:      "CONNECTION_CLOSE",
			frameType: FrameTypeConnectionClose,
			frame:     &ConnectionCloseFrame{IsApplicationError: false, ReasonPhrase: "foobar"},
		},
		{
			name:      "APPLICATION_CLOSE",
			frameType: FrameTypeApplicationClose,
			frame:     &ConnectionCloseFrame{IsApplicationError: true, ReasonPhrase: "foobar"},
		},
		{
			name:      "HANDSHAKE_DONE",
			frameType: FrameTypeHandshakeDone,
			frame:     &HandshakeDoneFrame{},
		},
		{
			name:      "RESET_STREAM_AT",
			frameType: FrameTypeResetStreamAt,
			frame:     &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parser := NewFrameParser(true, true)
			b, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)

			frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
			require.NoError(t, err)
			require.Equal(t, test.frameType, frameType)
			require.Equal(t, 1, l)

			frame, l, err := parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, test.frame, frame)
			require.Equal(t, len(b)-1, l)
		})
	}
}

func TestFrameAllowedAtEncLevel(t *testing.T) {
	type testCase struct {
		name             string
		frameType        FrameType
		frame            Frame
		allowedInitial   bool
		allowedHandshake bool
		allowedZeroRTT   bool
		allowedOneRTT    bool
	}

	for _, tc := range []testCase{
		{
			name:             "CRYPTO_FRAME",
			frameType:        FrameTypeCrypto,
			frame:            &CryptoFrame{Offset: 0, Data: []byte("foo")},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "ACK_FRAME",
			frameType:        FrameTypeAck,
			frame:            &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 1}}},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "CONNECTION_CLOSE_FRAME",
			frameType:        FrameTypeConnectionClose,
			frame:            &ConnectionCloseFrame{IsApplicationError: false, ReasonPhrase: "err"},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "PING_FRAME",
			frameType:        FrameTypePing,
			frame:            &PingFrame{},
			allowedInitial:   true,
			allowedHandshake: true,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
		{
			name:             "NEW_TOKEN_FRAME",
			frameType:        FrameTypeNewToken,
			frame:            &NewTokenFrame{Token: []byte("tok")},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "PATH_RESPONSE_FRAME",
			frameType:        FrameTypePathResponse,
			frame:            &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "RETIRE_CONNECTION_ID_FRAME",
			frameType:        FrameTypeRetireConnectionID,
			frame:            &RetireConnectionIDFrame{SequenceNumber: 1},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   false,
			allowedOneRTT:    true,
		},
		{
			name:             "MAX_DATA_FRAME",
			frameType:        FrameTypeMaxData,
			frame:            &MaxDataFrame{MaximumData: 1},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
		{
			name:             "STREAM_FRAME",
			frameType:        FrameType(0x8),
			frame:            &StreamFrame{StreamID: 1, Data: []byte("foobar")},
			allowedInitial:   false,
			allowedHandshake: false,
			allowedZeroRTT:   true,
			allowedOneRTT:    true,
		},
	} {
		for _, encLevel := range []protocol.EncryptionLevel{
			protocol.EncryptionInitial,
			protocol.EncryptionHandshake,
			protocol.Encryption0RTT,
			protocol.Encryption1RTT,
		} {
			t.Run(fmt.Sprintf("%s/%v", tc.name, encLevel), func(t *testing.T) {
				var allowed bool
				switch encLevel {
				case protocol.EncryptionInitial:
					allowed = tc.allowedInitial
				case protocol.EncryptionHandshake:
					allowed = tc.allowedHandshake
				case protocol.Encryption0RTT:
					allowed = tc.allowedZeroRTT
				case protocol.Encryption1RTT:
					allowed = tc.allowedOneRTT
				}

				parser := NewFrameParser(true, true)
				b, err := tc.frame.Append(nil, protocol.Version1)
				require.NoError(t, err)
				frameType, _, err := parser.ParseType(b, encLevel)
				if allowed {
					require.NoError(t, err)
					require.Equal(t, tc.frameType, frameType)
				} else {
					require.Error(t, err)
					var transportErr *qerr.TransportError
					require.ErrorAs(t, err, &transportErr)
					require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
				}
			})
		}
	}
}

func TestFrameParserDatagramFrame(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &DatagramFrame{
		Data: []byte("foobar"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	frameType, l, err := parser.ParseType(b, protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeDatagramNoLength, frameType)
	require.Equal(t, 1, l)

	// ParseLessCommonFrame should not be used to handle DATAGRAM frames
	_, _, err = parser.ParseLessCommonFrame(frameType, b[l:], protocol.Version1)
	require.Error(t, err)

	// parseDatagramFrame should be used for this type
	datagramFrame, l, err := parser.ParseDatagramFrame(frameType, b[l:], protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &DatagramFrame{}, datagramFrame)
	require.Equal(t, 6, l)
	require.Equal(t, f.Data, datagramFrame.Data)
}

func TestFrameParserDatagramUnsupported(t *testing.T) {
	parser := NewFrameParser(false, true)
	f := &DatagramFrame{Data: []byte("foobar")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
	checkFrameUnsupported(t, err, 0x30)
}

func TestFrameParserResetStreamAtUnsupported(t *testing.T) {
	parser := NewFrameParser(true, false)
	f := &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	_, _, err = parser.ParseType(b, protocol.Encryption1RTT)
	checkFrameUnsupported(t, err, 0x24)
}

func TestFrameParserInvalidFrameType(t *testing.T) {
	parser := NewFrameParser(true, true)

	_, l, err := parser.ParseType(encodeVarInt(0x42), protocol.Encryption1RTT)

	require.Equal(t, 2, l)

	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
}

func TestFrameParsingErrorsOnInvalidFrames(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &MaxStreamDataFrame{
		StreamID:          0x1337,
		MaximumStreamData: 0xdeadbeef,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	frameType, l, err := parser.ParseType(b[:len(b)-2], protocol.Encryption1RTT)
	require.NoError(t, err)
	require.Equal(t, FrameTypeMaxStreamData, frameType)
	require.Equal(t, 1, l)

	_, _, err = parser.ParseLessCommonFrame(frameType, b[1:len(b)-2], protocol.Version1)
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
}

func writeFrames(tb testing.TB, frames ...Frame) []byte {
	var b []byte
	for _, f := range frames {
		var err error
		b, err = f.Append(b, protocol.Version1)
		require.NoError(tb, err)
	}
	return b
}

// This function is used in benchmarks, and also to ensure zero allocation for STREAM frame parsing.
// We can therefore not use the require framework, as it allocates.
func parseFrames(tb testing.TB, parser *FrameParser, data []byte, frames ...Frame) {
	for _, expectedFrame := range frames {
		frameType, l, err := parser.ParseType(data, protocol.Encryption1RTT)
		if err != nil {
			tb.Fatal(err)
		}
		data = data[l:]

		if frameType.IsStreamFrameType() {
			sf := expectedFrame.(*StreamFrame)
			frame, l, err := ParseStreamFrame(data, frameType, protocol.Version1)
			if err != nil {
				tb.Fatal(err)
			}
			if sf.StreamID != frame.StreamID || sf.Offset != frame.Offset {
				tb.Fatalf("STREAM frame does not match: %v vs %v", sf, frame)
			}
			frame.PutBack()
			data = data[l:]
			continue
		}

		if frameType.IsAckFrameType() {
			af, ok := expectedFrame.(*AckFrame)
			if !ok {
				tb.Fatalf("expected ACK, but got %v", expectedFrame)
			}

			f, l, err := parser.ParseAckFrame(frameType, data, protocol.Encryption1RTT, protocol.Version1)
			if f.DelayTime != af.DelayTime || f.ECNCE != af.ECNCE || f.ECT0 != af.ECT0 || f.ECT1 != af.ECT1 {
				tb.Fatal(err)
			}
			if f.DelayTime != af.DelayTime {
				tb.Fatalf("ACK frame does not match: %v vs %v", af, f)
			}
			if !slices.Equal(f.AckRanges, af.AckRanges) {
				tb.Fatalf("ACK frame ACK ranges don't match: %v vs %v", af, f)
			}
			data = data[l:]
			continue
		}

		if frameType.IsDatagramFrameType() {
			df, ok := expectedFrame.(*DatagramFrame)
			if !ok {
				tb.Fatalf("expected DATAGRAM, but got %v", expectedFrame)
			}

			f, l, err := parser.ParseDatagramFrame(frameType, data, protocol.Version1)
			if err != nil {
				tb.Fatal(err)
			}
			if df.DataLenPresent != f.DataLenPresent || !bytes.Equal(df.Data, f.Data) {
				tb.Fatalf("DATAGRAM frame does not match: %v vs %v", df, f)
			}
			data = data[l:]
			continue
		}

		f, l, err := parser.ParseLessCommonFrame(frameType, data, protocol.Version1)
		if err != nil {
			tb.Fatal(err)
		}
		data = data[l:]

		switch frameType {
		case FrameTypeMaxData:
			mdf, ok := expectedFrame.(*MaxDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_DATA, but got %v", expectedFrame)
			}
			if *f.(*MaxDataFrame) != *mdf {
				tb.Fatalf("MAX_DATA frame does not match: %v vs %v", f, mdf)
			}
		case FrameTypeUniMaxStreams:
			msf, ok := expectedFrame.(*MaxStreamsFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAMS, but got %v", expectedFrame)
			}
			if *f.(*MaxStreamsFrame) != *msf {
				tb.Fatalf("MAX_STREAMS frame does not match: %v vs %v", f, msf)
			}
		case FrameTypeMaxStreamData:
			mdf, ok := expectedFrame.(*MaxStreamDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAM_DATA, but got %v", expectedFrame)
			}
			if *f.(*MaxStreamDataFrame) != *mdf {
				tb.Fatalf("MAX_STREAM_DATA frame does not match: %v vs %v", f, mdf)
			}
		case FrameTypeCrypto:
			cf, ok := expectedFrame.(*CryptoFrame)
			if !ok {
				tb.Fatalf("expected CRYPTO, but got %v", expectedFrame)
			}
			frame := f.(*CryptoFrame)
			if frame.Offset != cf.Offset || !bytes.Equal(frame.Data, cf.Data) {
				tb.Fatalf("CRYPTO frame does not match: %v vs %v", f, cf)
			}
		case FrameTypePing:
			_ = f.(*PingFrame)
		case FrameTypeResetStream:
			rsf, ok := expectedFrame.(*ResetStreamFrame)
			if !ok {
				tb.Fatalf("expected RESET_STREAM, but got %v", expectedFrame)
			}
			if *f.(*ResetStreamFrame) != *rsf {
				tb.Fatalf("RESET_STREAM frame does not match: %v vs %v", f, rsf)
			}
			continue
		default:
			tb.Fatalf("Frame type not supported in benchmark or should not occur: %v", frameType)
		}
	}
}

func TestFrameParserAllocs(t *testing.T) {
	t.Run("STREAM", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &StreamFrame{
				StreamID:       protocol.StreamID(1337 + i),
				Offset:         protocol.ByteCount(1e7 + i),
				Data:           make([]byte, 200+i),
				DataLenPresent: true,
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})

	t.Run("ACK", func(t *testing.T) {
		var frames []Frame
		for i := range 10 {
			frames = append(frames, &AckFrame{
				AckRanges: []AckRange{
					{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
					{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
				},
				DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
				ECT0:      uint64(5000 + i),
				ECT1:      uint64(i),
				ECNCE:     uint64(10 + i),
			})
		}
		require.Zero(t, testFrameParserAllocs(t, frames))
	})
}

func testFrameParserAllocs(t *testing.T, frames []Frame) float64 {
	buf := writeFrames(t, frames...)
	parser := NewFrameParser(true, true)
	parser.SetAckDelayExponent(3)

	return testing.AllocsPerRun(100, func() {
		parseFrames(t, parser, buf, frames...)
	})
}

func BenchmarkParseOtherFrames(b *testing.B) {
	frames := []Frame{
		&MaxDataFrame{MaximumData: 123456},
		&MaxStreamsFrame{MaxStreamNum: 10},
		&MaxStreamDataFrame{StreamID: 1337, MaximumStreamData: 1e6},
		&CryptoFrame{Offset: 1000, Data: make([]byte, 128)},
		&PingFrame{},
		&ResetStreamFrame{StreamID: 87654, ErrorCode: 1234, FinalSize: 1e8},
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseAckFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		frames = append(frames, &AckFrame{
			AckRanges: []AckRange{
				{Smallest: protocol.PacketNumber(5000 + i), Largest: protocol.PacketNumber(5200 + i)},
				{Smallest: protocol.PacketNumber(1 + i), Largest: protocol.PacketNumber(4200 + i)},
			},
			DelayTime: time.Duration(int64(time.Millisecond) * int64(i)),
			ECT0:      uint64(5000 + i),
			ECT1:      uint64(i),
			ECNCE:     uint64(10 + i),
		})
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseStreamFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		data := make([]byte, 200+i)
		rand.Read(data)
		frames = append(frames, &StreamFrame{
			StreamID:       protocol.StreamID(1337 + i),
			Offset:         protocol.ByteCount(1e7 + i),
			Data:           data,
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseDatagramFrame(b *testing.B) {
	var frames []Frame
	for i := range 10 {
		data := make([]byte, 200+i)
		rand.Read(data)
		frames = append(frames, &DatagramFrame{
			Data:           data,
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}

func benchmarkFrames(b *testing.B, frames ...Frame) {
	buf := writeFrames(b, frames...)

	parser := NewFrameParser(true, true)
	parser.SetAckDelayExponent(3)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		parseFrames(b, parser, buf, frames...)
	}
}
