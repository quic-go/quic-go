package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Buffer Pool", func() {
	It("returns buffers of correct len and cap", func() {
		buf := getPacketBuffer()
		Expect(buf).To(HaveLen(0))
		Expect(buf).To(HaveCap(int(protocol.MaxReceivePacketSize)))
	})

	It("zeroes put buffers' length", func() {
		for i := 0; i < 1000; i++ {
			buf := getPacketBuffer()
			putPacketBuffer(buf[0:10])
			buf = getPacketBuffer()
			Expect(buf).To(HaveLen(0))
			Expect(buf).To(HaveCap(int(protocol.MaxReceivePacketSize)))
		}
	})

	It("panics if wrong-sized buffers are passed", func() {
		Expect(func() {
			putPacketBuffer([]byte{0})
		}).To(Panic())
	})
})
