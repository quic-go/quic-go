package wire

import (
	"bytes"
	"testing"
	"time"

	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestLogFrameNoDebug(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	logger.SetLogLevel(utils.LogLevelInfo)
	LogFrame(logger, &ResetStreamFrame{}, true)
	require.Zero(t, buf.Len())
}

func TestLogSentFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	LogFrame(logger, &ResetStreamFrame{}, true)
	require.Contains(t, buf.String(), "\t-> &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x0, FinalSize: 0}\n")
}

func TestLogReceivedFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	LogFrame(logger, &ResetStreamFrame{}, false)
	require.Contains(t, buf.String(), "\t<- &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x0, FinalSize: 0}\n")
}

func TestLogCryptoFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &CryptoFrame{
		Offset: 42,
		Data:   make([]byte, 123),
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.CryptoFrame{Offset: 42, Data length: 123, Offset + Data length: 165}\n")
}

func TestLogStreamFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &StreamFrame{
		StreamID: 42,
		Offset:   1337,
		Data:     bytes.Repeat([]byte{'f'}, 100),
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.StreamFrame{StreamID: 42, Fin: false, Offset: 1337, Data length: 100, Offset + Data length: 1437}\n")
}

func TestLogAckFrameWithoutMissingPackets(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &AckFrame{
		AckRanges: []AckRange{{Smallest: 42, Largest: 1337}},
		DelayTime: 1 * time.Millisecond,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.AckFrame{LargestAcked: 1337, LowestAcked: 42, DelayTime: 1ms}\n")
}

func TestLogAckFrameWithECN(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &AckFrame{
		AckRanges: []AckRange{{Smallest: 42, Largest: 1337}},
		DelayTime: 1 * time.Millisecond,
		ECT0:      5,
		ECT1:      66,
		ECNCE:     777,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.AckFrame{LargestAcked: 1337, LowestAcked: 42, DelayTime: 1ms, ECT0: 5, ECT1: 66, CE: 777}\n")
}

func TestLogAckFrameWithMissingPackets(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &AckFrame{
		AckRanges: []AckRange{
			{Smallest: 5, Largest: 8},
			{Smallest: 2, Largest: 3},
		},
		DelayTime: 12 * time.Millisecond,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.AckFrame{LargestAcked: 8, LowestAcked: 2, AckRanges: {{Largest: 8, Smallest: 5}, {Largest: 3, Smallest: 2}}, DelayTime: 12ms}\n")
}

func TestLogMaxStreamsFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &MaxStreamsFrame{
		Type:         protocol.StreamTypeBidi,
		MaxStreamNum: 42,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.MaxStreamsFrame{Type: bidi, MaxStreamNum: 42}\n")
}

func TestLogMaxDataFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &MaxDataFrame{
		MaximumData: 42,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.MaxDataFrame{MaximumData: 42}\n")
}

func TestLogMaxStreamDataFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &MaxStreamDataFrame{
		StreamID:          10,
		MaximumStreamData: 42,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.MaxStreamDataFrame{StreamID: 10, MaximumStreamData: 42}\n")
}

func TestLogDataBlockedFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &DataBlockedFrame{
		MaximumData: 1000,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.DataBlockedFrame{MaximumData: 1000}\n")
}

func TestLogStreamDataBlockedFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &StreamDataBlockedFrame{
		StreamID:          42,
		MaximumStreamData: 1000,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 1000}\n")
}

func TestLogStreamsBlockedFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	frame := &StreamsBlockedFrame{
		Type:        protocol.StreamTypeBidi,
		StreamLimit: 42,
	}
	LogFrame(logger, frame, false)
	require.Contains(t, buf.String(), "\t<- &wire.StreamsBlockedFrame{Type: bidi, MaxStreams: 42}\n")
}

func TestLogNewConnectionIDFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	LogFrame(logger, &NewConnectionIDFrame{
		SequenceNumber:      42,
		RetirePriorTo:       24,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10},
	}, false)
	require.Contains(t, buf.String(), "\t<- &wire.NewConnectionIDFrame{SequenceNumber: 42, RetirePriorTo: 24, ConnectionID: deadbeef, StatelessResetToken: 0x0102030405060708090a0b0c0d0e0f10}")
}

func TestLogRetireConnectionIDFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	LogFrame(logger, &RetireConnectionIDFrame{SequenceNumber: 42}, false)
	require.Contains(t, buf.String(), "\t<- &wire.RetireConnectionIDFrame{SequenceNumber: 42}")
}

func TestLogNewTokenFrame(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := setupLogTest(t, buf)
	LogFrame(logger, &NewTokenFrame{
		Token: []byte{0xde, 0xad, 0xbe, 0xef},
	}, true)
	require.Contains(t, buf.String(), "\t-> &wire.NewTokenFrame{Token: 0xdeadbeef")
}
