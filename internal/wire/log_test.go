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
		buf bytes.Buffer
	)

	BeforeEach(func() {
		buf.Reset()
		utils.SetLogLevel(utils.LogLevelDebug)
		log.SetOutput(&buf)
	})

	AfterSuite(func() {
		utils.SetLogLevel(utils.LogLevelNothing)
		log.SetOutput(os.Stdout)
	})

	It("doesn't log when debug is disabled", func() {
		utils.SetLogLevel(utils.LogLevelInfo)
		LogFrame(&RstStreamFrame{}, true)
		Expect(buf.Len()).To(BeZero())
	})

	It("logs sent frames", func() {
		LogFrame(&RstStreamFrame{}, true)
		Expect(buf.Bytes()).To(ContainSubstring("\t-> &wire.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs received frames", func() {
		LogFrame(&RstStreamFrame{}, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs stream frames", func() {
		frame := &StreamFrame{
			StreamID: 42,
			Offset:   0x1337,
			Data:     bytes.Repeat([]byte{'f'}, 0x100),
		}
		LogFrame(frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.StreamFrame{StreamID: 42, FinBit: false, Offset: 0x1337, Data length: 0x100, Offset + Data length: 0x1437}\n"))
	})

	It("logs ACK frames", func() {
		frame := &AckFrame{
			LargestAcked: 0x1337,
			LowestAcked:  0x42,
			DelayTime:    1 * time.Millisecond,
		}
		LogFrame(frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 0x1337, LowestAcked: 0x42, AckRanges: []wire.AckRange(nil), DelayTime: 1ms}\n"))
	})

	It("logs incoming StopWaiting frames", func() {
		frame := &StopWaitingFrame{
			LeastUnacked: 0x1337,
		}
		LogFrame(frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.StopWaitingFrame{LeastUnacked: 0x1337}\n"))
	})

	It("logs outgoing StopWaiting frames", func() {
		frame := &StopWaitingFrame{
			LeastUnacked:    0x1337,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		LogFrame(frame, true)
		Expect(buf.Bytes()).To(ContainSubstring("\t-> &wire.StopWaitingFrame{LeastUnacked: 0x1337, PacketNumberLen: 0x4}\n"))
	})
})
