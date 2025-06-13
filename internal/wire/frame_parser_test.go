package wire

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/qerr"

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

// STREAM and ACK are the most relevant frames for high-throughput transfers.
func BenchmarkParseStreamAndACK(b *testing.B) {
	ack := &AckFrame{
		AckRanges: []AckRange{
			{Smallest: 5000, Largest: 5200},
			{Smallest: 1, Largest: 4200},
		},
		DelayTime: 42 * time.Millisecond,
		ECT0:      5000,
		ECT1:      0,
		ECNCE:     10,
	}
	sf := &StreamFrame{
		StreamID:       1337,
		Offset:         1e7,
		Data:           make([]byte, 200),
		DataLenPresent: true,
	}
	rand.Read(sf.Data)

	data, err := ack.Append([]byte{}, protocol.Version1)
	if err != nil {
		b.Fatal(err)
	}
	data, err = sf.Append(data, protocol.Version1)
	if err != nil {
		b.Fatal(err)
	}

	parser := NewFrameParser(false, false)
	parser.SetAckDelayExponent(3)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l, f, err := parser.ParseNext(data, protocol.Encryption1RTT, protocol.Version1)
		if err != nil {
			b.Fatal(err)
		}
		ackParsed := f.(*AckFrame)
		if ackParsed.DelayTime != ack.DelayTime || ackParsed.ECNCE != ack.ECNCE {
			b.Fatalf("incorrect ACK frame: %v vs %v", ack, ackParsed)
		}
		l2, f, err := parser.ParseNext(data[l:], protocol.Encryption1RTT, protocol.Version1)
		if err != nil {
			b.Fatal(err)
		}
		if len(data[l:]) != l2 {
			b.Fatal("didn't parse the entire packet")
		}
		sfParsed := f.(*StreamFrame)
		if sfParsed.StreamID != sf.StreamID || !bytes.Equal(sfParsed.Data, sf.Data) {
			b.Fatalf("incorrect STREAM frame: %v vs %v", sf, sfParsed)
		}
	}
}

func BenchmarkParseOtherFrames(b *testing.B) {
	maxDataFrame := &MaxDataFrame{MaximumData: 123456}
	maxStreamsFrame := &MaxStreamsFrame{MaxStreamNum: 10}
	maxStreamDataFrame := &MaxStreamDataFrame{StreamID: 1337, MaximumStreamData: 1e6}
	cryptoFrame := &CryptoFrame{Offset: 1000, Data: make([]byte, 128)}
	resetStreamFrame := &ResetStreamFrame{StreamID: 87654, ErrorCode: 1234, FinalSize: 1e8}
	rand.Read(cryptoFrame.Data)
	frames := []Frame{
		maxDataFrame,
		maxStreamsFrame,
		maxStreamDataFrame,
		cryptoFrame,
		&PingFrame{},
		resetStreamFrame,
	}
	var buf []byte
	for i, frame := range frames {
		var err error
		buf, err = frame.Append(buf, protocol.Version1)
		if err != nil {
			b.Fatal(err)
		}
		if i == len(frames)/2 {
			// add 3 PADDING frames
			buf = append(buf, 0)
			buf = append(buf, 0)
			buf = append(buf, 0)
		}
	}

	parser := NewFrameParser(false, false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		data := buf
		for j := 0; j < len(frames); j++ {
			l, f, err := parser.ParseNext(data, protocol.Encryption1RTT, protocol.Version1)
			if err != nil {
				b.Fatal(err)
			}
			data = data[l:]
			switch j {
			case 0:
				if f.(*MaxDataFrame).MaximumData != maxDataFrame.MaximumData {
					b.Fatalf("MAX_DATA frame does not match: %v vs %v", f, maxDataFrame)
				}
			case 1:
				if f.(*MaxStreamsFrame).MaxStreamNum != maxStreamsFrame.MaxStreamNum {
					b.Fatalf("MAX_STREAMS frame does not match: %v vs %v", f, maxStreamsFrame)
				}
			case 2:
				if f.(*MaxStreamDataFrame).StreamID != maxStreamDataFrame.StreamID ||
					f.(*MaxStreamDataFrame).MaximumStreamData != maxStreamDataFrame.MaximumStreamData {
					b.Fatalf("MAX_STREAM_DATA frame does not match: %v vs %v", f, maxStreamDataFrame)
				}
			case 3:
				if f.(*CryptoFrame).Offset != cryptoFrame.Offset || !bytes.Equal(f.(*CryptoFrame).Data, cryptoFrame.Data) {
					b.Fatalf("CRYPTO frame does not match: %v vs %v", f, cryptoFrame)
				}
			case 4:
				_ = f.(*PingFrame)
			case 5:
				rst := f.(*ResetStreamFrame)
				if rst.StreamID != resetStreamFrame.StreamID || rst.ErrorCode != resetStreamFrame.ErrorCode ||
					rst.FinalSize != resetStreamFrame.FinalSize {
					b.Fatalf("RESET_STREAM frame does not match: %v vs %v", rst, resetStreamFrame)
				}
			}
		}
	}
}
