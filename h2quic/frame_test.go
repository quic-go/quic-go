package h2quic

import (
	"encoding/binary"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/net/http2"
)

var _ = Describe("HTTP2/QUIC frames", func() {
	It("Construct a valid PUSH_PROMISE frame", func() {
		pushStreamID := protocol.StreamID(6)
		httpHeader := []byte("[HTTP HEADER]")
		pushPromiseFrame, err := PushPromiseFrame(pushStreamID, httpHeader)
		Expect(err).To(Not(HaveOccurred()))
		testPushPromiseFrame(pushStreamID, pushPromiseFrame, len(httpHeader))
	})
})

// Only checks length if blockFragmentSize >= 0
func testPushPromiseFrame(pushStreamID protocol.StreamID, frame []byte, blockFragmentSize int) {
	indexStart := 0
	indexEnd := indexStart + 2 // length is 2 byte
	length := binary.BigEndian.Uint16(frame[indexStart:indexEnd])
	if blockFragmentSize >= 0 {
		Expect(length).To(Equal(uint16(blockFragmentSize + 4))) // 4 from promisedID
		Expect(length).To(Equal(uint16(len(frame) - frameHeaderLen)))
	}
	indexStart = indexEnd
	indexEnd = indexStart + 1 // frame type is 1 byte
	frameType := http2.FrameType(frame[indexStart:indexEnd][0])
	Expect(frameType).To(Equal(http2.FramePushPromise))
	// PromisedID
	indexStart = indexEnd + 1 // skip flags (1 byte)
	indexEnd = indexStart + 4 // promisedID is 4 bytes
	promisedID := binary.BigEndian.Uint32(frame[indexStart:indexEnd])
	Expect(promisedID).To(Equal(uint32(pushStreamID)))
}
