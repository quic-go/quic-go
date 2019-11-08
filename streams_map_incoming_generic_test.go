package quic

import (
	"context"
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockGenericStream struct {
	num protocol.StreamNum

	closed   bool
	closeErr error
}

func (s *mockGenericStream) closeForShutdown(err error) {
	s.closed = true
	s.closeErr = err
}

var _ = Describe("Streams Map (incoming)", func() {
	const (
		maxNumStreams uint64 = 5
	)

	var (
		m              *incomingItemsMap
		newItemCounter int
		mockSender     *MockStreamSender
	)

	BeforeEach(func() {
		newItemCounter = 0
		mockSender = NewMockStreamSender(mockCtrl)
		m = newIncomingItemsMap(
			func(num protocol.StreamNum) item {
				newItemCounter++
				return &mockGenericStream{num: num}
			},
			maxNumStreams,
			mockSender.queueControlFrame,
		)
	})

	It("opens all streams up to the id on GetOrOpenStream", func() {
		_, err := m.GetOrOpenStream(4)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(4))
	})

	It("starts opening streams at the right position", func() {
		// like the test above, but with 2 calls to GetOrOpenStream
		_, err := m.GetOrOpenStream(2)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(2))
		_, err = m.GetOrOpenStream(5)
		Expect(err).ToNot(HaveOccurred())
		Expect(newItemCounter).To(Equal(5))
	})

	It("accepts streams in the right order", func() {
		_, err := m.GetOrOpenStream(2) // open streams 1 and 2
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		str, err = m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
	})

	It("allows opening the maximum stream ID", func() {
		str, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
	})

	It("errors when trying to get a stream ID higher than the maximum", func() {
		_, err := m.GetOrOpenStream(6)
		Expect(err).To(HaveOccurred())
		Expect(err.(streamError).TestError()).To(MatchError("peer tried to open stream 6 (current limit: 5)"))
	})

	It("blocks AcceptStream until a new stream is available", func() {
		strChan := make(chan item)
		go func() {
			defer GinkgoRecover()
			str, err := m.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()
		Consistently(strChan).ShouldNot(Receive())
		str, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		var acceptedStr item
		Eventually(strChan).Should(Receive(&acceptedStr))
		Expect(acceptedStr.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
	})

	It("unblocks AcceptStream when the context is canceled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := m.AcceptStream(ctx)
			Expect(err).To(MatchError("context canceled"))
			close(done)
		}()
		Consistently(done).ShouldNot(BeClosed())
		cancel()
		Eventually(done).Should(BeClosed())
	})

	It("unblocks AcceptStream when it is closed", func() {
		testErr := errors.New("test error")
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := m.AcceptStream(context.Background())
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
		_, err := m.AcceptStream(context.Background())
		Expect(err).To(MatchError(testErr))
	})

	It("closes all streams when CloseWithError is called", func() {
		str1, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		str2, err := m.GetOrOpenStream(3)
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
		_, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		str, err := m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		Expect(m.DeleteStream(1)).To(Succeed())
		str, err = m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
	})

	It("waits until a stream is accepted before actually deleting it", func() {
		_, err := m.GetOrOpenStream(2)
		Expect(err).ToNot(HaveOccurred())
		Expect(m.DeleteStream(2)).To(Succeed())
		str, err := m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		mockSender.EXPECT().queueControlFrame(gomock.Any())
		str, err = m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
	})

	It("doesn't return a stream queued for deleting from GetOrOpenStream", func() {
		str, err := m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
		Expect(m.DeleteStream(1)).To(Succeed())
		str, err = m.GetOrOpenStream(1)
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(BeNil())
		// when accepting this stream, it will get deleted, and a MAX_STREAMS frame is queued
		mockSender.EXPECT().queueControlFrame(gomock.Any())
		str, err = m.AcceptStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str).ToNot(BeNil())
	})

	It("errors when deleting a non-existing stream", func() {
		err := m.DeleteStream(1337)
		Expect(err).To(HaveOccurred())
		Expect(err.(streamError).TestError()).To(MatchError("Tried to delete unknown incoming stream 1337"))
	})

	It("sends MAX_STREAMS frames when streams are deleted", func() {
		// open a bunch of streams
		_, err := m.GetOrOpenStream(5)
		Expect(err).ToNot(HaveOccurred())
		// accept all streams
		for i := 0; i < 5; i++ {
			_, err := m.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
		}
		mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
			Expect(f.(*wire.MaxStreamsFrame).MaxStreamNum).To(Equal(protocol.StreamNum(maxNumStreams + 1)))
		})
		Expect(m.DeleteStream(3)).To(Succeed())
		mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
			Expect(f.(*wire.MaxStreamsFrame).MaxStreamNum).To(Equal(protocol.StreamNum(maxNumStreams + 2)))
		})
		Expect(m.DeleteStream(4)).To(Succeed())
	})
})
