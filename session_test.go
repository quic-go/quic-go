package quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

var _ = Describe("Session", func() {
	var (
		session        *Session
		callbackCalled bool
	)

	BeforeEach(func() {
		callbackCalled = false
		session = &Session{
			Streams:        make(map[protocol.StreamID]*Stream),
			streamCallback: func(*Session, *Stream) { callbackCalled = true },
		}
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.Streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.Streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.Streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.Streams).To(HaveLen(1))
			p := make([]byte, 4)
			_, err := session.Streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("closes streams", func() {

		})

		It("rejects streams that existed previously", func() {

		})
	})
})
