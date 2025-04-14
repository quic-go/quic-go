package wire

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/stretchr/testify/require"
)

func TestFrameParsingReturnsNilWhenNothingToRead(t *testing.T) {
	parser := NewFrameParser(true)
	l, f, err := parser.ParseNext(nil, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Zero(t, l)
	require.Nil(t, f)
}

func TestFrameParsingSkipsPaddingFrames(t *testing.T) {
	parser := NewFrameParser(true)
	b := []byte{0, 0} // 2 PADDING frames
	b, err := (&PingFrame{}).Append(b, protocol.Version1)
	require.NoError(t, err)
	l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, &PingFrame{}, f)
	require.Equal(t, 2+1, l)
}

func TestFrameParsingHandlesPaddingAtEnd(t *testing.T) {
	parser := NewFrameParser(true)
	l, f, err := parser.ParseNext([]byte{0, 0, 0}, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, f)
	require.Equal(t, 3, l)
}

func TestFrameParsingParsesSingleFrame(t *testing.T) {
	parser := NewFrameParser(true)
	var b []byte
	for i := 0; i < 10; i++ {
		var err error
		b, err = (&PingFrame{}).Append(b, protocol.Version1)
		require.NoError(t, err)
	}
	l, f, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &PingFrame{}, f)
	require.Equal(t, 1, l)
}

func TestFrameParsingUnpacksAckFrames(t *testing.T) {
	parser := NewFrameParser(true)
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

func TestFrameParsingUsesCustomAckDelayExponentFor1RTTPackets(t *testing.T) {
	parser := NewFrameParser(true)
	parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: time.Second,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, 4*time.Second, frame.(*AckFrame).DelayTime)
}

func TestFrameParsingUsesDefaultAckDelayExponentForNon1RTTPackets(t *testing.T) {
	parser := NewFrameParser(true)
	parser.SetAckDelayExponent(protocol.AckDelayExponent + 2)
	f := &AckFrame{
		AckRanges: []AckRange{{Smallest: 1, Largest: 1}},
		DelayTime: time.Second,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, frame, err := parser.ParseNext(b, protocol.EncryptionHandshake, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, time.Second, frame.(*AckFrame).DelayTime)
}

func TestFrameParsingUnpacksResetStreamFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &ResetStreamFrame{
		StreamID:  0xdeadbeef,
		FinalSize: 0xdecafbad1234,
		ErrorCode: 0x1337,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksStopSendingFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &StopSendingFrame{StreamID: 0x42}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksCryptoFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &CryptoFrame{
		Offset: 0x1337,
		Data:   []byte("lorem ipsum"),
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksNewTokenFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &NewTokenFrame{Token: []byte("foobar")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksStreamFrames(t *testing.T) {
	parser := NewFrameParser(true)
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

func TestFrameParsingUnpacksMaxDataFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &MaxDataFrame{MaximumData: 0xcafe}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksMaxStreamDataFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &MaxStreamDataFrame{
		StreamID:          0xdeadbeef,
		MaximumStreamData: 0xdecafbad,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksMaxStreamsFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &MaxStreamsFrame{
		Type:         protocol.StreamTypeBidi,
		MaxStreamNum: 0x1337,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksDataBlockedFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &DataBlockedFrame{MaximumData: 0x1234}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksStreamDataBlockedFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &StreamDataBlockedFrame{
		StreamID:          0xdeadbeef,
		MaximumStreamData: 0xdead,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksStreamsBlockedFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &StreamsBlockedFrame{
		Type:        protocol.StreamTypeBidi,
		StreamLimit: 0x1234567,
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksNewConnectionIDFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &NewConnectionIDFrame{
		SequenceNumber:      0x1337,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksRetireConnectionIDFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &RetireConnectionIDFrame{SequenceNumber: 0x1337}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksPathChallengeFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.IsType(t, &PathChallengeFrame{}, frame)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, frame.(*PathChallengeFrame).Data)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksPathResponseFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, frame)
	require.IsType(t, &PathResponseFrame{}, frame)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, frame.(*PathResponseFrame).Data)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksConnectionCloseFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &ConnectionCloseFrame{
		IsApplicationError: true,
		ReasonPhrase:       "foobar",
	}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksHandshakeDoneFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &HandshakeDoneFrame{}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingUnpacksDatagramFrames(t *testing.T) {
	parser := NewFrameParser(true)
	f := &DatagramFrame{Data: []byte("foobar")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	l, frame, err := parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, f, frame)
	require.Equal(t, len(b), l)
}

func TestFrameParsingErrorsWhenDatagramFramesAreNotSupported(t *testing.T) {
	parser := NewFrameParser(false)
	f := &DatagramFrame{Data: []byte("foobar")}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	_, _, err = parser.ParseNext(b, protocol.Encryption1RTT, protocol.Version1)
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, uint64(0x30), transportErr.FrameType)
	require.Equal(t, "unknown frame type", transportErr.ErrorMessage)
}

func TestFrameParsingErrorsOnInvalidType(t *testing.T) {
	parser := NewFrameParser(true)
	_, _, err := parser.ParseNext(encodeVarInt(0x42), protocol.Encryption1RTT, protocol.Version1)
	require.Error(t, err)
	var transportErr *qerr.TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, qerr.FrameEncodingError, transportErr.ErrorCode)
	require.Equal(t, uint64(0x42), transportErr.FrameType)
	require.Equal(t, "unknown frame type", transportErr.ErrorMessage)
}

func TestFrameParsingErrorsOnInvalidFrames(t *testing.T) {
	parser := NewFrameParser(true)
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

	parser := NewFrameParser(false)
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

	parser := NewFrameParser(false)

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
