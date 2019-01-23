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

type mockGenericStream struct {
	id protocol.StreamID

	closed   bool
	closeErr error
}

func (s *mockGenericStream) closeForShutdown(err error) {
	s.closed = true
	s.closeErr = err
}

var _ = Describe("Streams Map (incoming)", func() {
	const (
		firstNewStream   protocol.StreamID = 2
		maxNumStreams    uint64            = 5
		initialMaxStream protocol.StreamID = firstNewStream + 4*protocol.StreamID(maxNumStreams-1)
	)

	var (
		m              *incomingItemsMap
		newItem        func(id protocol.StreamID) item
		newItemCounter int
		mockSender     *MockStreamSender
	)

	BeforeEach(func() {
		newItemCounter = 0
		newItem = func(id protocol.StreamID) item {
			newItemCounter++
			return &mockGenericStream{id: id}
		}
		mockSender = NewMockStreamSender(mockCtrl)
		m = newIncomingItemsMap(firstNewStream, initialMaxStream, maxNumStreams, mockSender.queueControlFrame, newItem)
	})

	It("opens all streams up to the id on GetOrOpenStream", func() {
		_, err := m.GetOrOpenStream(firstNewStream + 4*4)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(5))
	})

	It("starts opening streams at the right position", func() {
		// like the test above, but with 2 calls to GetOrOpenStream
		_, err := m.GetOrOpenStream(firstNewStream + 4)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(2))
		_, err = m.GetOrOpenStream(firstNewStream + 4*4)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(5))
	})

	It("accepts streams in the right order", func() {
		_, err := m.GetOrOpenStream(firstNewStream + 4) // open stream 20 and 24
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
		str, err = m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream + 4))
	})

	It("allows opening the maximum stream ID", func() {
		str, err := m.GetOrOpenStream(initialMaxStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(initialMaxStream))
	})

	It("errors when trying to get a stream ID higher than the maximum", func() {
		_, err := m.GetOrOpenStream(initialMaxStream + 4)
		Expect(err).To(MatchError(fmt.Errorf("peer tried to open stream %d (current limit: %d)", initialMaxStream+4, initialMaxStream)))
	})

	It("blocks AcceptStream until a new stream is available", func() {
		strChan := make(chan item)
		go func() {
			defer GinkgoRecover()
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()
		Consistently(strChan).ShouldNot(Receive())
		str, err := m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
		var acceptedStr item
		Eventually(strChan).Should(Receive(&acceptedStr))
		Expect(acceptedStr.(*mockGenericStream).id).To(Equal(firstNewStream))
	})

	It("works with stream 0", func() {
		m = newIncomingItemsMap(0, 1000, 1000, mockSender.queueControlFrame, newItem)
		strChan := make(chan item)
		go func() {
			defer GinkgoRecover()
			str, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()
		Consistently(strChan).ShouldNot(Receive())
		str, err := m.GetOrOpenStream(0)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(BeZero())
		var acceptedStr item
		Eventually(strChan).Should(Receive(&acceptedStr))
		Expect(acceptedStr.(*mockGenericStream).id).To(BeZero())
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

	It("closes all streams when CloseWithError is called", func() {
		str1, err := m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		str2, err := m.GetOrOpenStream(firstNewStream + 8)
		Expect(err).ToNot(HaveOccurred())
		testErr := errors.New("test err")
		m.CloseWithError(testErr)
		Expect(str1.(*mockGenericStream).closed).To(BeTrue())
		Expect(str1.(*mockGenericStream).closeErr).To(MatchError(testErr))
		Expect(str2.(*mockGenericStream).closed).To(BeTrue())
		Expect(str2.(*mockGenericStream).closeErr).To(MatchError(testErr))
	})

	It("deletes streams", func() {
		mockSender.EXPECT().queueControlFrame(gomock.Any())
		_, err := m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
		Expect(m.DeleteStream(firstNewStream)).To(Succeed())
		str, err = m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
	})

	It("waits until a stream is accepted before actually deleting it", func() {
		_, err := m.GetOrOpenStream(firstNewStream + 4)
		Expect(err).ToNot(HaveOccurred())
		Expect(m.DeleteStream(firstNewStream + 4)).To(Succeed())
		str, err := m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream))
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		mockSender.EXPECT().queueControlFrame(gomock.Any())
		str, err = m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).id).To(Equal(firstNewStream + 4))
	})

	It("doesn't return a stream queued for deleting from GetOrOpenStream", func() {
		str, err := m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
		Expect(m.DeleteStream(firstNewStream)).To(Succeed())
		str, err = m.GetOrOpenStream(firstNewStream)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		mockSender.EXPECT().queueControlFrame(gomock.Any())
		str, err = m.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
	})

	It("errors when deleting a non-existing stream", func() {
		err := m.DeleteStream(1337)
		Expect(err).To(MatchError("Tried to delete unknown stream 1337"))
	})

	It("sends MAX_STREAMS frames when streams are deleted", func() {
		// open a bunch of streams
		_, err := m.GetOrOpenStream(firstNewStream + 4*4)
		Expect(err).ToNot(HaveOccurred())
		// accept all streams
		for i := 0; i < 5; i++ {
			_, err := m.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
		}
		mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
			Expect(f.(*wire.MaxStreamsFrame).MaxStreams).To(Equal(maxNumStreams + 1))
		})
		Expect(m.DeleteStream(firstNewStream + 2*4)).To(Succeed())
		mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
			Expect(f.(*wire.MaxStreamsFrame).MaxStreams).To(Equal(maxNumStreams + 2))
		})
		Expect(m.DeleteStream(firstNewStream + 3*4)).To(Succeed())
	})
})
