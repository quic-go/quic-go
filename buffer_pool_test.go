package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Buffer Pool", func() {
	It("returns buffers of cap", func() {
		buf := getPacketBuffer()
		Expect(buf.Slice).To(HaveCap(int(protocol.MaxReceivePacketSize)))
	})

	It("puts buffers back", func() {
		buf := getPacketBuffer()
		putPacketBuffer(buf)
	})

	It("panics if wrong-sized buffers are passed", func() {
		buf := getPacketBuffer()
		buf.Slice = make([]byte, 10)
		Expect(func() { putPacketBuffer(buf) }).To(Panic())
	})

	It("panics if it is put pack twice", func() {
		buf := getPacketBuffer()
		putPacketBuffer(buf)
		Expect(func() { putPacketBuffer(buf) }).To(Panic())
	})
})
