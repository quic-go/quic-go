package frames

import (
	"bytes"
	"os"

	"github.com/lucas-clemente/quic-go/utils"

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
		utils.SetLogWriter(&buf)
	})

	AfterSuite(func() {
		utils.SetLogLevel(utils.LogLevelNothing)
		utils.SetLogWriter(os.Stdout)
	})

	It("doesn't log when debug is disabled", func() {
		utils.SetLogLevel(utils.LogLevelInfo)
		LogFrame(&RstStreamFrame{}, true)
		Expect(buf.Len()).To(BeZero())
	})

	It("logs sent frames", func() {
		LogFrame(&RstStreamFrame{}, true)
		Expect(string(buf.Bytes())).To(Equal("\t-> &frames.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs received frames", func() {
		LogFrame(&RstStreamFrame{}, false)
		Expect(string(buf.Bytes())).To(Equal("\t<- &frames.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs stream frames", func() {
		LogFrame(&StreamFrame{}, false)
		Expect(string(buf.Bytes())).To(Equal("\t<- &frames.StreamFrame{StreamID: 0, FinBit: false, Offset: 0x0, Data length: 0x0, Offset + Data length: 0x0}\n"))
	})
})
