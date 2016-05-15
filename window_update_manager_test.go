package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WindowUpdateManager", func() {
	var wum *WindowUpdateManager

	BeforeEach(func() {
		wum = NewWindowUpdateManager()
	})

	Context("queueing new window updates", func() {
		It("queues a window update for a new stream", func() {
			wum.SetStreamOffset(5, 0x1000)
			Expect(wum.streamOffsets).To(HaveKey(protocol.StreamID(5)))
			Expect(wum.streamOffsets[5].Offset).To(Equal(protocol.ByteCount(0x1000)))
		})

		It("updates the offset for an existing stream", func() {
			wum.SetStreamOffset(5, 0x1000)
			wum.SetStreamOffset(5, 0x2000)
			Expect(wum.streamOffsets).To(HaveKey(protocol.StreamID(5)))
			Expect(wum.streamOffsets[5].Offset).To(Equal(protocol.ByteCount(0x2000)))
		})

		It("does not decrease the offset for an existing stream", func() {
			wum.SetStreamOffset(5, 0x1000)
			wum.SetStreamOffset(5, 0x500)
			Expect(wum.streamOffsets).To(HaveKey(protocol.StreamID(5)))
			Expect(wum.streamOffsets[5].Offset).To(Equal(protocol.ByteCount(0x1000)))
		})

		It("resets the counter after increasing the offset", func() {
			wum.streamOffsets[5] = &windowUpdateItem{
				Offset:  0x1000,
				Counter: 1,
			}
			wum.SetStreamOffset(5, 0x2000)
			Expect(wum.streamOffsets[5].Offset).To(Equal(protocol.ByteCount(0x2000)))
			Expect(wum.streamOffsets[5].Counter).To(Equal(uint8(0)))
		})
	})

	Context("dequeueing window updates", func() {
		BeforeEach(func() {
			wum.SetStreamOffset(7, 0x1000)
			wum.SetStreamOffset(9, 0x500)
		})

		It("gets the window update frames", func() {
			f := wum.GetWindowUpdateFrames()
			Expect(f).To(HaveLen(2))
			Expect(f).To(ContainElement(&frames.WindowUpdateFrame{StreamID: 7, ByteOffset: 0x1000}))
			Expect(f).To(ContainElement(&frames.WindowUpdateFrame{StreamID: 9, ByteOffset: 0x500}))
		})

		It("increases the counter", func() {
			_ = wum.GetWindowUpdateFrames()
			Expect(wum.streamOffsets[7].Counter).To(Equal(uint8(1)))
			Expect(wum.streamOffsets[9].Counter).To(Equal(uint8(1)))
		})

		It("only sends out a window update frame WindowUpdateNumRepitions times", func() {
			for i := uint8(0); i < protocol.WindowUpdateNumRepitions; i++ {
				frames := wum.GetWindowUpdateFrames()
				Expect(frames).To(HaveLen(2))
			}
			frames := wum.GetWindowUpdateFrames()
			Expect(frames).To(BeEmpty())
		})
	})
})
