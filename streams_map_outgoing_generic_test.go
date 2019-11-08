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

var _ = Describe("Streams Map (outgoing)", func() {
	var (
		m          *outgoingItemsMap
		newItem    func(num protocol.StreamNum) item
		mockSender *MockStreamSender
	)

	BeforeEach(func() {
		newItem = func(num protocol.StreamNum) item {
			return &mockGenericStream{num: num}
		}
		mockSender = NewMockStreamSender(mockCtrl)
		m = newOutgoingItemsMap(newItem, mockSender.queueControlFrame)
	})

	Context("no stream ID limit", func() {
		BeforeEach(func() {
			m.SetMaxStream(0xffffffff)
		})

		It("opens streams", func() {
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
			str, err = m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
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
			str, err := m.GetStream(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		})

		It("errors when trying to get a stream that has not yet been opened", func() {
			_, err := m.GetStream(1)
			Expect(err).To(HaveOccurred())
			Expect(err.(streamError).TestError()).To(MatchError("peer attempted to open stream 1"))
		})

		It("deletes streams", func() {
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(m.DeleteStream(1)).To(Succeed())
			Expect(err).ToNot(HaveOccurred())
			str, err := m.GetStream(1)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("errors when deleting a non-existing stream", func() {
			err := m.DeleteStream(1337)
			Expect(err).To(HaveOccurred())
			Expect(err.(streamError).TestError()).To(MatchError("Tried to delete unknown outgoing stream 1337"))
		})

		It("errors when deleting a stream twice", func() {
			_, err := m.OpenStream() // opens firstNewStream
			Expect(err).ToNot(HaveOccurred())
			Expect(m.DeleteStream(1)).To(Succeed())
			err = m.DeleteStream(1)
			Expect(err).To(HaveOccurred())
			Expect(err.(streamError).TestError()).To(MatchError("Tried to delete unknown outgoing stream 1"))
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

		It("returns immediately when called with a canceled context", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := m.OpenStreamSync(ctx)
			Expect(err).To(MatchError("context canceled"))
		})

		It("blocks until a stream can be opened synchronously", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			m.SetMaxStream(1)
			Eventually(done).Should(BeClosed())
		})

		It("unblocks when the context is canceled", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(ctx)
				Expect(err).To(MatchError("context canceled"))
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			cancel()
			Eventually(done).Should(BeClosed())

			// make sure that the next stream openend is stream 1
			m.SetMaxStream(1000)
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
		})

		It("opens streams in the right order", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
				close(done1)
			}()
			Consistently(done1).ShouldNot(BeClosed())
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
				close(done2)
			}()
			Consistently(done2).ShouldNot(BeClosed())

			m.SetMaxStream(1)
			Eventually(done1).Should(BeClosed())
			Consistently(done2).ShouldNot(BeClosed())
			m.SetMaxStream(2)
			Eventually(done2).Should(BeClosed())
		})

		It("unblocks multiple OpenStreamSync calls at the same time", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				done <- struct{}{}
			}()
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				done <- struct{}{}
			}()
			Consistently(done).ShouldNot(Receive())
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(context.Background())
				Expect(err).To(MatchError("test done"))
				done <- struct{}{}
			}()
			Consistently(done).ShouldNot(Receive())

			m.SetMaxStream(2)
			Eventually(done).Should(Receive())
			Eventually(done).Should(Receive())
			Consistently(done).ShouldNot(Receive())

			m.CloseWithError(errors.New("test done"))
			Eventually(done).Should(Receive())
		})

		It("returns an error for OpenStream while an OpenStreamSync call is blocking", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).MaxTimes(2)
			openedSync := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(1)))
				close(openedSync)
			}()
			Consistently(openedSync).ShouldNot(BeClosed())

			start := make(chan struct{})
			openend := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				var hasStarted bool
				for {
					str, err := m.OpenStream()
					if err == nil {
						Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
						close(openend)
						return
					}
					expectTooManyStreamsError(err)
					if !hasStarted {
						close(start)
						hasStarted = true
					}
				}
			}()

			Eventually(start).Should(BeClosed())
			m.SetMaxStream(1)
			Eventually(openedSync).Should(BeClosed())
			Consistently(openend).ShouldNot(BeClosed())
			m.SetMaxStream(2)
			Eventually(openend).Should(BeClosed())
		})

		It("stops opening synchronously when it is closed", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			testErr := errors.New("test error")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(context.Background())
				Expect(err).To(MatchError(testErr))
				close(done)
			}()

			Consistently(done).ShouldNot(BeClosed())
			m.CloseWithError(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("doesn't reduce the stream limit", func() {
			m.SetMaxStream(2)
			m.SetMaxStream(1)
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.(*mockGenericStream).num).To(Equal(protocol.StreamNum(2)))
		})

		It("queues a STREAM_ID_BLOCKED frame if no stream can be opened", func() {
			m.SetMaxStream(6)
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
			m.SetMaxStream(1)
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
