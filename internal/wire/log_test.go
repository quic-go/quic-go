package wire

import (
	"bytes"
	"log"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
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
		Expect(buf.Bytes()).To(ContainSubstring("\t-> &wire.ResetStreamFrame{StreamID:0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs received frames", func() {
		LogFrame(logger, &ResetStreamFrame{}, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.ResetStreamFrame{StreamID:0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs CRYPTO frames", func() {
		frame := &CryptoFrame{
			Offset: 0x42,
			Data:   make([]byte, 0x123),
		}
		LogFrame(logger, frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.CryptoFrame{Offset: 0x42, Data length: 0x123, Offset + Data length: 0x165}\n"))

	})

	It("logs STREAM frames", func() {
		frame := &StreamFrame{
			StreamID: 42,
			Offset:   0x1337,
			Data:     bytes.Repeat([]byte{'f'}, 0x100),
		}
		LogFrame(logger, frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.StreamFrame{StreamID: 42, FinBit: false, Offset: 0x1337, Data length: 0x100, Offset + Data length: 0x1437}\n"))
	})

	It("logs ACK frames without missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{{Smallest: 0x42, Largest: 0x1337}},
			DelayTime: 1 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 0x1337, LowestAcked: 0x42, DelayTime: 1ms}\n"))
	})

	It("logs ACK frames with missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{
				{Smallest: 0x5, Largest: 0x8},
				{Smallest: 0x2, Largest: 0x3},
			},
			DelayTime: 12 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 0x8, LowestAcked: 0x2, AckRanges: {{Largest: 0x8, Smallest: 0x5}, {Largest: 0x3, Smallest: 0x2}}, DelayTime: 12ms}\n"))
	})

	It("logs MAX_STREAMS frames", func() {
		frame := &MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: 42,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.MaxStreamsFrame{Type: bidi, MaxStreamNum: 42}\n"))
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
			ConnectionID:        protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			StatelessResetToken: [16]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10},
		}, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.NewConnectionIDFrame{SequenceNumber: 42, ConnectionID: 0xdeadbeef, StatelessResetToken: 0x0102030405060708090a0b0c0d0e0f10}"))
	})

	It("logs NEW_TOKEN frames", func() {
		LogFrame(logger, &NewTokenFrame{
			Token: []byte{0xde, 0xad, 0xbe, 0xef},
		}, true)
		Expect(buf.String()).To(ContainSubstring("\t-> &wire.NewTokenFrame{Token: 0xdeadbeef"))
	})
})
