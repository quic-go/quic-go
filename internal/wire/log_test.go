package wire

import (
	"bytes"
	"log"
	"os"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame logging", func() {
	var (
		buf    *bytes.Buffer
		logger utils.Logger
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		logger = utils.DefaultLogger
		logger.SetLogLevel(utils.LogLevelDebug)
		log.SetOutput(buf)
	})

	AfterEach(func() {
		log.SetOutput(os.Stdout)
	})

	It("doesn't log when debug is disabled", func() {
		logger.SetLogLevel(utils.LogLevelInfo)
		LogFrame(logger, &ResetStreamFrame{}, true)
		Expect(buf.Len()).To(BeZero())
	})

	It("logs sent frames", func() {
		LogFrame(logger, &ResetStreamFrame{}, true)
		Expect(buf.String()).To(ContainSubstring("\t-> &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x0, FinalSize: 0}\n"))
	})

	It("logs received frames", func() {
		LogFrame(logger, &ResetStreamFrame{}, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x0, FinalSize: 0}\n"))
	})

	It("logs CRYPTO frames", func() {
		frame := &CryptoFrame{
			Offset: 42,
			Data:   make([]byte, 123),
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.CryptoFrame{Offset: 42, Data length: 123, Offset + Data length: 165}\n"))
	})

	It("logs STREAM frames", func() {
		frame := &StreamFrame{
			StreamID: 42,
			Offset:   1337,
			Data:     bytes.Repeat([]byte{'f'}, 100),
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.StreamFrame{StreamID: 42, Fin: false, Offset: 1337, Data length: 100, Offset + Data length: 1437}\n"))
	})

	It("logs ACK frames without missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{{Smallest: 42, Largest: 1337}},
			DelayTime: 1 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 1337, LowestAcked: 42, DelayTime: 1ms}\n"))
	})

	It("logs ACK frames with ECN", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{{Smallest: 42, Largest: 1337}},
			DelayTime: 1 * time.Millisecond,
			ECT0:      5,
			ECT1:      66,
			ECNCE:     777,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 1337, LowestAcked: 42, DelayTime: 1ms, ECT0: 5, ECT1: 66, CE: 777}\n"))
	})

	It("logs ACK frames with missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{
				{Smallest: 5, Largest: 8},
				{Smallest: 2, Largest: 3},
			},
			DelayTime: 12 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 8, LowestAcked: 2, AckRanges: {{Largest: 8, Smallest: 5}, {Largest: 3, Smallest: 2}}, DelayTime: 12ms}\n"))
	})

	It("logs MAX_STREAMS frames", func() {
		frame := &MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 42,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.MaxStreamsFrame{Type: bidi, MaxStreamNum: 42}\n"))
	})

	It("logs MAX_DATA frames", func() {
		frame := &MaxDataFrame{
			MaximumData: 42,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.MaxDataFrame{MaximumData: 42}\n"))
	})

	It("logs MAX_STREAM_DATA frames", func() {
		frame := &MaxStreamDataFrame{
			StreamID:          10,
			MaximumStreamData: 42,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.MaxStreamDataFrame{StreamID: 10, MaximumStreamData: 42}\n"))
	})

	It("logs DATA_BLOCKED frames", func() {
		frame := &DataBlockedFrame{
			MaximumData: 1000,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.DataBlockedFrame{MaximumData: 1000}\n"))
	})

	It("logs STREAM_DATA_BLOCKED frames", func() {
		frame := &StreamDataBlockedFrame{
			StreamID:          42,
			MaximumStreamData: 1000,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.StreamDataBlockedFrame{StreamID: 42, MaximumStreamData: 1000}\n"))
	})

	It("logs STREAMS_BLOCKED frames", func() {
		frame := &StreamsBlockedFrame{
			Type:        protocol.StreamTypeBidi,
			StreamLimit: 42,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.StreamsBlockedFrame{Type: bidi, MaxStreams: 42}\n"))
	})

	It("logs NEW_CONNECTION_ID frames", func() {
		LogFrame(logger, &NewConnectionIDFrame{
			SequenceNumber:      42,
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: protocol.StatelessResetToken{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10},
		}, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.NewConnectionIDFrame{SequenceNumber: 42, ConnectionID: deadbeef, StatelessResetToken: 0x0102030405060708090a0b0c0d0e0f10}"))
	})

	It("logs NEW_TOKEN frames", func() {
		LogFrame(logger, &NewTokenFrame{
			Token: []byte{0xde, 0xad, 0xbe, 0xef},
		}, true)
		Expect(buf.String()).To(ContainSubstring("\t-> &wire.NewTokenFrame{Token: 0xdeadbeef"))
	})
})
