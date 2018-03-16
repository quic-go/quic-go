package quic

import (
	"errors"
	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (incoming)", func() {
	const (
		firstNewStream                     = 3
		maxNumStreams    int               = 10
		initialMaxStream protocol.StreamID = firstNewStream + 4*protocol.StreamID(maxNumStreams-1)
	)

	var (
		m          *incomingItemsMap
		newItem    func(id protocol.StreamID) item
		mockSender *MockStreamSender
	)

	BeforeEach(func() {
		newItem = func(id protocol.StreamID) item { return id }
		mockSender = NewMockStreamSender(mockCtrl)
		m = newIncomingItemsMap(firstNewStream, initialMaxStream, maxNumStreams, mockSender.queueControlFrame, newItem)
	})

	Context("opening streams", func() {
		It("opens the first stream", func() {
			str, err := m.GetOrOpenStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(firstNewStream)))
		})

		It("opens a higher stream", func() {
			str, err := m.GetOrOpenStream(firstNewStream + 20)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(firstNewStream + 20)))
		})

		It("returns previously opened streams", func() {
			_, err := m.GetOrOpenStream(firstNewStream + 10)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.GetOrOpenStream(firstNewStream + 10 + 4)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetOrOpenStream(firstNewStream + 10)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(firstNewStream + 10)))
			str, err = m.GetOrOpenStream(firstNewStream + 10 + 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(firstNewStream + 10 + 4)))
		})

		It("allows opening the maximum stream ID", func() {
			str, err := m.GetOrOpenStream(initialMaxStream)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(initialMaxStream))
		})

		It("errors when trying to get a stream ID higher than the maximum", func() {
			_, err := m.GetOrOpenStream(initialMaxStream + 4)
			Expect(err).To(MatchError(fmt.Errorf("peer tried to open stream %d (current limit: %d)", initialMaxStream+4, initialMaxStream)))
		})
	})

	Context("accepting streams", func() {
		It("blocks AcceptStream until a new stream is available", func() {
			strChan := make(chan item)
			go func() {
				defer GinkgoRecover()
				str, err := m.AcceptStream()
				Expect(err).ToNot(HaveOccurred())
				strChan <- str
			}()
			Consistently(strChan).ShouldNot(Receive())
			str, err := m.GetOrOpenStream(3)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(3)))
			Eventually(strChan).Should(Receive(Equal(protocol.StreamID(3))))
		})

		It("accepts streams in the right order", func() {
			_, err := m.GetOrOpenStream(19 + 4)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.GetOrOpenStream(19)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(19 + 4)))
			str, err = m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(19)))
		})

		// This can happen for a unidirectional stream that was reset.
		It("accepts a stream that was closed", func() {
			_, err := m.GetOrOpenStream(23)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(23)
			Expect(err).ToNot(HaveOccurred())
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(protocol.StreamID(23)))
		})

		It("unblocks AcceptStream when it is closed", func() {
			testErr := errors.New("test error")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := m.AcceptStream()
				Expect(err).To(MatchError(testErr))
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())
			m.CloseWithError(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("errors AcceptStream immediately if it is closed", func() {
			testErr := errors.New("test error")
			m.CloseWithError(testErr)
			_, err := m.AcceptStream()
			Expect(err).To(MatchError(testErr))
		})
	})

	Context("deleting streams", func() {
		It("deletes streams", func() {
			_, err := m.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(5)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("doesn't reopen a closed stream", func() {
			id := protocol.StreamID(firstNewStream + 20)
			_, err := m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(id)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("doesn't reopen a closed stream, if a lower stream was opened afterwards", func() {
			id := protocol.StreamID(firstNewStream + 20)
			_, err := m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(id)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.GetOrOpenStream(id - 4)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("errors when deleting a non-existing stream", func() {
			err := m.DeleteStream(1337)
			Expect(err).To(MatchError("Tried to delete unknown stream 1337"))
		})

		It("errors when deleting a stream that has not yet been opened", func() {
			_, err := m.GetOrOpenStream(5 + 4)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(5)
			Expect(err).To(MatchError("Tried to delete unknown stream 5"))
		})
	})

	Context("sending MAX_STREAM_ID frames", func() {
		It("sends a MAX_STREAM_ID frame when the lowest stream is deleted", func() {
			_, err := m.GetOrOpenStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			mockSender.EXPECT().queueControlFrame(&wire.MaxStreamIDFrame{StreamID: initialMaxStream + 4})
			err = m.DeleteStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
		})

		It("sends a MAX_STREAM_ID frame when the highest stream is deleted", func() {
			_, err := m.GetOrOpenStream(initialMaxStream)
			Expect(err).ToNot(HaveOccurred())
			_, err = m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			mockSender.EXPECT().queueControlFrame(&wire.MaxStreamIDFrame{StreamID: initialMaxStream + 4})
			err = m.DeleteStream(initialMaxStream)
			Expect(err).ToNot(HaveOccurred())
		})

		It("sends a MAX_STREAM_ID frame when a deleted stream is accepted", func() {
			id := protocol.StreamID(firstNewStream + 12)
			_, err := m.GetOrOpenStream(id)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(id)
			Expect(err).ToNot(HaveOccurred())
			mockSender.EXPECT().queueControlFrame(&wire.MaxStreamIDFrame{StreamID: initialMaxStream + 4})
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(id))
		})
	})
})
