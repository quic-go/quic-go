package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Buffer Pool", func() {
	It("returns buffers of cap", func() {
		buf1 := getPacketBuffer()
		Expect(buf1.Data).To(HaveCap(protocol.MaxPacketBufferSize))
		buf2 := getLargePacketBuffer()
		Expect(buf2.Data).To(HaveCap(protocol.MaxLargePacketBufferSize))
	})

	It("releases buffers", func() {
		buf1 := getPacketBuffer()
		buf1.Release()
		buf2 := getLargePacketBuffer()
		buf2.Release()
	})

	It("gets the length", func() {
		buf := getPacketBuffer()
		buf.Data = append(buf.Data, []byte("foobar")...)
		Expect(buf.Len()).To(BeEquivalentTo(6))
	})

	It("panics if wrong-sized buffers are passed", func() {
		buf := getPacketBuffer()
		buf.Data = make([]byte, 10)
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
