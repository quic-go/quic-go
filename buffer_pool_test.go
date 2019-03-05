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

	It("releases buffers", func() {
		buf := getPacketBuffer()
		buf.Release()
	})

	It("panics if wrong-sized buffers are passed", func() {
		buf := getPacketBuffer()
		buf.Slice = make([]byte, 10)
		Expect(func() { buf.Release() }).To(Panic())
	})

	It("panics if it is released twice", func() {
		buf := getPacketBuffer()
		buf.Release()
		Expect(func() { buf.Release() }).To(Panic())
	})

	It("panics if it is decremented too many times", func() {
		buf := getPacketBuffer()
		buf.Decrement()
		Expect(func() { buf.Decrement() }).To(Panic())
	})

	It("waits until all parts have been released", func() {
		buf := getPacketBuffer()
		buf.Split()
		buf.Split()
		// now we have 3 parts
		buf.Decrement()
		buf.Decrement()
		buf.Decrement()
		Expect(func() { buf.Decrement() }).To(Panic())
	})
})
