package quic

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WindowUpdateManager", func() {
	var bm *blockedManager

	BeforeEach(func() {
		bm = newBlockedManager()
	})

	It("accepts new entries", func() {
		bm.AddBlockedStream(1337, 0x1337)
		Expect(bm.blockedStreams).To(HaveKey(protocol.StreamID(1337)))
		Expect(bm.blockedStreams[1337]).To(Equal(protocol.ByteCount(0x1337)))
	})

	It("gets a blocked frame for the right offset", func() {
		bm.AddBlockedStream(1337, 0x1337)
		Expect(bm.GetBlockedFrame(1337, 0x1337)).To(Equal(&frames.BlockedFrame{StreamID: 1337}))
	})

	It("doesn't get a blocked frame twice for the same offset", func() {
		bm.AddBlockedStream(1337, 0x1337)
		Expect(bm.GetBlockedFrame(1337, 0x1337)).ToNot(BeNil())
		Expect(bm.GetBlockedFrame(1337, 0x1337)).To(BeNil())
	})

	It("doesn't get a blocked frame for smaller offsets", func() {
		bm.AddBlockedStream(1337, 0x1337)
		Expect(bm.GetBlockedFrame(1337, 0x1336)).To(BeNil())
	})

	It("doesn't get a blocked frame for the wrong stream", func() {
		bm.AddBlockedStream(1337, 0x1337)
		Expect(bm.GetBlockedFrame(1336, 0x1337)).To(BeNil())
	})
})
