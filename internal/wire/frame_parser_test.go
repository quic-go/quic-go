package wire

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/stretchr/testify/require"
)

func TestFrameParsingReturnsNilWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true, true)
	l, f, err := parser.ParseNext(nil, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.Nil(t, f)
}

func TestFrameParsingSkipsPaddingFrames(t *testing.T) {
	parser := NewFrameParser(true, true)
	b := []byte{0, 0} // 2 PADDING frames
	b, err := (&PingFrame{}).Append(b, protocol.Version1)
	require.NoError(t, err)
	l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, &PingFrame{}, f)
	require.Equal(t, 2+1, l)
}

func TestFrameParsingHandlesPaddingAtEnd(t *testing.T) {
	parser := NewFrameParser(true, true)
	l, f, err := parser.ParseNext([]byte{0, 0, 0}, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, f)
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
	l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &PingFrame{}, f)
	require.Equal(t, 1, l)
}

func TestFrameParserACK(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.IsType(t, f, frame)
	require.Equal(t, protocol.PacketNumber(0x13), frame.(*AckFrame).LargestAcked())
	require.Equal(t, len(b), l)
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
	_, frame, err := parser.ParseNext(b, encLevel, protocol.Version1)
	require.NoError(t, err)
	if encLevel == protocol.Encryption1RTT {
		require.Equal(t, 4*time.Second, frame.(*AckFrame).DelayTime)
	} else {
		require.Equal(t, time.Second, frame.(*AckFrame).DelayTime)
	}
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
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParserFrames(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name:  "MAX_DATA",
			frame: &MaxDataFrame{MaximumData: 0xcafe},
		},
		{
			name:  "MAX_STREAM_DATA",
			frame: &MaxStreamDataFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdecafbad},
		},
		{
			name: "RESET_STREAM",
			frame: &ResetStreamFrame{
				StreamID:  0xdeadbeef,
				FinalSize: 0xdecafbad1234,
				ErrorCode: 0x1337,
			},
		},
		{
			name:  "STOP_SENDING",
			frame: &StopSendingFrame{StreamID: 0x42},
		},
		{
			name:  "CRYPTO",
			frame: &CryptoFrame{Offset: 0x1337, Data: []byte("lorem ipsum")},
		},
		{
			name:  "NEW_TOKEN",
			frame: &NewTokenFrame{Token: []byte("foobar")},
		},
		{
			name:  "MAX_STREAMS",
			frame: &MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 0x1337},
		},
		{
			name:  "DATA_BLOCKED",
			frame: &DataBlockedFrame{MaximumData: 0x1234},
		},
		{
			name:  "STREAM_DATA_BLOCKED",
			frame: &StreamDataBlockedFrame{StreamID: 0xdeadbeef, MaximumStreamData: 0xdead},
		},
		{
			name:  "STREAMS_BLOCKED",
			frame: &StreamsBlockedFrame{Type: protocol.StreamTypeBidi, StreamLimit: 0x1234567},
		},
		{
			name: "NEW_CONNECTION_ID",
			frame: &NewConnectionIDFrame{
				SequenceNumber:      0x1337,
				ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
				StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			},
		},
		{
			name:  "RETIRE_CONNECTION_ID",
			frame: &RetireConnectionIDFrame{SequenceNumber: 0x1337},
		},
		{
			name:  "PATH_CHALLENGE",
			frame: &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:  "PATH_RESPONSE",
			frame: &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		},
		{
			name:  "CONNECTION_CLOSE",
			frame: &ConnectionCloseFrame{IsApplicationError: true, ReasonPhrase: "foobar"},
		},
		{
			name:  "HANDSHAKE_DONE",
			frame: &HandshakeDoneFrame{},
		},
		{
			name:  "DATAGRAM",
			frame: &DatagramFrame{Data: []byte("foobar")},
		},
		{
			name:  "RESET_STREAM_AT",
			frame: &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parser := NewFrameParser(true, true)
			b, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
			require.NoError(t, err)
			require.Equal(t, test.frame, frame)
			require.Equal(t, len(b), l)
		})
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

func TestFrameParserDatagramUnsupported(t *testing.T) {
	parser := NewFrameParser(false, true)
	f := &DatagramFrame{Data: []byte("foobar")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, err = parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	checkFrameUnsupported(t, err, 0x30)
}

func TestFrameParserResetStreamAtUnsupported(t *testing.T) {
	parser := NewFrameParser(true, false)
	f := &ResetStreamFrame{StreamID: 0x1337, ReliableSize: 0x42, FinalSize: 0xdeadbeef}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, err = parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	checkFrameUnsupported(t, err, 0x24)
}

func TestFrameParserInvalidFrameType(t *testing.T) {
	parser := NewFrameParser(true, true)
	_, _, err := parser.ParseNext(encodeVarInt(0x42), protocol.Encryption1RTT, protocol.Version1)
	checkFrameUnsupported(t, err, 0x42)
}

func TestFrameParsingErrorsOnInvalidFrames(t *testing.T) {
	parser := NewFrameParser(true, true)
	f := &MaxStreamDataFrame{
		StreamID:          0x1337,
		MaximumStreamData: 0xdeadbeef,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, err = parser.ParseNext(b[:len(b)-2], protocol.Encryption1RTT, protocol.Version1)
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

// This function is used in a benchmark, and also to ensure 0 allocations for StreamFrames
// require causes allocations, we thus need to test manually.
func parseFrames(tb testing.TB, parser *FrameParser, data []byte, frames ...Frame) {
	for _, expectedFrame := range frames {
		l, frame, err := parser.ParseNext(data, protocol.Encryption1RTT, protocol.Version1)
		if err != nil {
			tb.Fatal(err)
		}
		data = data[l:]
		if frame == nil {
			break
		}

		// Use type switch approach (like master branch)
		switch f := frame.(type) {
		case *StreamFrame:
			streamFrame := expectedFrame.(*StreamFrame)
			if streamFrame.StreamID != f.StreamID || streamFrame.Offset != f.Offset {
				tb.Fatalf("STREAM frame does not match: %v vs %v", streamFrame, f)
			}
		case *AckFrame:
			af, ok := expectedFrame.(*AckFrame)
			if !ok {
				tb.Fatalf("expected ACK, but got %v", expectedFrame)
			}
			if f.DelayTime != af.DelayTime {
				tb.Fatalf("ACK frame does not match: %v vs %v", af, f)
			}
			if !slices.Equal(f.AckRanges, af.AckRanges) {
				tb.Fatalf("ACK frame does not match, len(AckRanges) not equal: %v vs %v", af, f)
			}
		case *DatagramFrame:
			df, ok := expectedFrame.(*DatagramFrame)
			if !ok {
				tb.Fatalf("expected DATAGRAM, but got %v", expectedFrame)
			}
			if df.DataLenPresent != f.DataLenPresent || !bytes.Equal(df.Data, f.Data) {
				tb.Fatalf("DATAGRAM frame does not match: %v vs %v", df, f)
			}
		case *MaxDataFrame:
			mdf, ok := expectedFrame.(*MaxDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_DATA, but got %v", expectedFrame)
			}
			if *f != *mdf {
				tb.Fatalf("MAX_DATA frame does not match: %v vs %v", f, mdf)
			}
		case *MaxStreamsFrame:
			msf, ok := expectedFrame.(*MaxStreamsFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAMS, but got %v", expectedFrame)
			}
			if *f != *msf {
				tb.Fatalf("MAX_STREAMS frame does not match: %v vs %v", f, msf)
			}
		case *MaxStreamDataFrame:
			mdf, ok := expectedFrame.(*MaxStreamDataFrame)
			if !ok {
				tb.Fatalf("expected MAX_STREAM_DATA, but got %v", expectedFrame)
			}
			if *f != *mdf {
				tb.Fatalf("MAX_STREAM_DATA frame does not match: %v vs %v", f, mdf)
			}
		case *CryptoFrame:
			cf, ok := expectedFrame.(*CryptoFrame)
			if !ok {
				tb.Fatalf("expected CRYPTO, but got %v", expectedFrame)
			}
			if f.Offset != cf.Offset || !bytes.Equal(f.Data, cf.Data) {
				tb.Fatalf("CRYPTO frame does not match: %v vs %v", f, cf)
			}
		case *PingFrame:
			_ = f
		case *ResetStreamFrame:
			rsf, ok := expectedFrame.(*ResetStreamFrame)
			if !ok {
				tb.Fatalf("expected RESET_STREAM, but got %v", expectedFrame)
			}
			if *f != *rsf {
				tb.Fatalf("RESET_STREAM frame does not match: %v vs %v", f, rsf)
			}
		default:
			tb.Fatalf("Frame type not supported in benchmark: %T", f)
		}
	}
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

// STREAM and ACK are the most relevant frames for high-throughput transfers.
func BenchmarkParseStreamAndACK(b *testing.B) {
	frames := []Frame{
		&AckFrame{
			AckRanges: []AckRange{
				{Smallest: 5000, Largest: 5200},
				{Smallest: 1, Largest: 4200},
			},
			DelayTime: 42 * time.Millisecond,
			ECT0:      5000,
			ECT1:      0,
			ECNCE:     10,
		},
		&StreamFrame{
			StreamID:       1337,
			Offset:         1e7,
			Data:           make([]byte, 200),
			DataLenPresent: true,
		},
	}
	benchmarkFrames(b, frames...)
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
		frames = append(frames, &StreamFrame{
			StreamID:       protocol.StreamID(1337 + i),
			Offset:         protocol.ByteCount(1e7 + i),
			Data:           make([]byte, 200+i),
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}

func BenchmarkParseDatagramFrame(b *testing.B) {
	var frames []Frame
	for range 10 {
		frames = append(frames, &DatagramFrame{
			Data:           make([]byte, 200),
			DataLenPresent: true,
		})
	}
	benchmarkFrames(b, frames...)
}
