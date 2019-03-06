package quic

import (
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (outgoing)", func() {
	const firstNewStream protocol.StreamID = 3

	var (
		m          *outgoingItemsMap
		newItem    func(id protocol.StreamID) item
		mockSender *MockStreamSender
	)

	BeforeEach(func() {
		newItem = func(id protocol.StreamID) item {
			return &mockGenericStream{id: id}
		}
		mockSender = NewMockStreamSender(mockCtrl)
		m = newOutgoingItemsMap(firstNewStream, newItem, mockSender.queueControlFrame)
	})

	Context("no stream ID limit", func() {
		BeforeEach(func() {
			m.SetMaxStream(0xffffffff)
		})

		It("opens streams", func() {
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
			str, err = m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream + 4))
		})

		It("doesn't open streams after it has been closed", func() {
			testErr := errors.New("close")
			m.CloseWithError(testErr)
			_, err := m.OpenStream()
			Expect(err).To(MatchError(testErr))
		})

		It("gets streams", func() {
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
		})

		It("errors when trying to get a stream that has not yet been opened", func() {
			_, err := m.GetStream(firstNewStream)
			Expect(err).To(MatchError(qerr.Error(qerr.StreamStateError, "peer attempted to open stream 3")))
		})

		It("deletes streams", func() {
			_, err := m.OpenStream() // opens firstNewStream
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("errors when deleting a non-existing stream", func() {
			err := m.DeleteStream(1337)
			Expect(err).To(MatchError("Tried to delete unknown stream 1337"))
		})

		It("errors when deleting a stream twice", func() {
			_, err := m.OpenStream() // opens firstNewStream
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(firstNewStream)
			Expect(err).ToNot(HaveOccurred())
			err = m.DeleteStream(firstNewStream)
			Expect(err).To(MatchError("Tried to delete unknown stream 3"))
		})

		It("closes all streams when CloseWithError is called", func() {
			str1, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str2, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			testErr := errors.New("test err")
			m.CloseWithError(testErr)
			Expect(str1.(*mockGenericStream).closed).To(BeTrue())
			Expect(str1.(*mockGenericStream).closeErr).To(MatchError(testErr))
			Expect(str2.(*mockGenericStream).closed).To(BeTrue())
			Expect(str2.(*mockGenericStream).closeErr).To(MatchError(testErr))
		})
	})

	Context("with stream ID limits", func() {
		It("errors when no stream can be opened immediately", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			_, err := m.OpenStream()
			expectTooManyStreamsError(err)
		})

		It("blocks until a stream can be opened synchronously", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync()
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			m.SetMaxStream(firstNewStream)
			Eventually(done).Should(BeClosed())
		})

		It("works with stream 0", func() {
			m = newOutgoingItemsMap(0, newItem, mockSender.queueControlFrame)
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeZero())
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync()
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).id).To(BeZero())
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			m.SetMaxStream(0)
			Eventually(done).Should(BeClosed())
		})

		It("stops opening synchronously when it is closed", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			testErr := errors.New("test error")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync()
				Expect(err).To(MatchError(testErr))
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			m.CloseWithError(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("doesn't reduce the stream limit", func() {
			m.SetMaxStream(firstNewStream + 4)
			m.SetMaxStream(firstNewStream)
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream + 4))
		})

		It("queues a STREAM_ID_BLOCKED frame if no stream can be opened", func() {
			m.SetMaxStream(firstNewStream + 5*4)
			// open the 6 allowed streams
			for i := 0; i < 6; i++ {
				_, err := m.OpenStream()
				Expect(err).ToNot(HaveOccurred())
			}

			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeEquivalentTo(6))
			})
			_, err := m.OpenStream()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(errTooManyOpenStreams.Error()))
		})

		It("only sends one STREAM_ID_BLOCKED frame for one stream ID", func() {
			m.SetMaxStream(firstNewStream)
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeEquivalentTo(1))
			})
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			// try to open a stream twice, but expect only one STREAM_ID_BLOCKED to be sent
			_, err = m.OpenStream()
			expectTooManyStreamsError(err)
			_, err = m.OpenStream()
			expectTooManyStreamsError(err)
		})
	})
})
