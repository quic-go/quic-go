package quic

import (
	"errors"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

var _ = Describe("Session", func() {
	var (
		session        *Session
		callbackCalled bool
	)

	BeforeEach(func() {
		callbackCalled = false
		session = &Session{
			streams:        make(map[protocol.StreamID]*stream),
			streamCallback: func(*Session, utils.Stream) { callbackCalled = true },
		}
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("closes streams with FIN bits", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(Equal(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = session.streams[5].Read(p)
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes empty streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			session.closeStreamsWithError(testErr)
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("rejects streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(io.EOF))
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(MatchError("Session: reopening streams is not allowed"))
		})
	})
})
