package quic

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Streams Map (outgoing)", func() {
	var (
		m          *outgoingStreamsMap[*mockGenericStream]
		newStr     func(num protocol.StreamNum) *mockGenericStream
		mockSender *MockStreamSender
	)

	const streamType = 42

	// waitForEnqueued waits until there are n go routines waiting on OpenStreamSync()
	waitForEnqueued := func(n int) {
		Eventually(func() int {
			m.mutex.Lock()
			defer m.mutex.Unlock()
			return len(m.openQueue)
		}, 50*time.Millisecond, 100*time.Microsecond).Should(Equal(n))
	}

	BeforeEach(func() {
		newStr = func(num protocol.StreamNum) *mockGenericStream {
			return &mockGenericStream{num: num}
		}
		mockSender = NewMockStreamSender(mockCtrl)
		m = newOutgoingStreamsMap[*mockGenericStream](streamType, newStr, mockSender.queueControlFrame)
	})

	Context("no stream ID limit", func() {
		BeforeEach(func() {
			m.SetMaxStream(0xffffffff)
		})

		It("opens streams", func() {
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.num).To(Equal(protocol.StreamNum(1)))
			str, err = m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.num).To(Equal(protocol.StreamNum(2)))
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
			Expect(str.num).To(Equal(protocol.StreamNum(1)))
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
			Expect(err.(streamError).TestError()).To(MatchError("tried to delete unknown outgoing stream 1337"))
		})

		It("errors when deleting a stream twice", func() {
			_, err := m.OpenStream() // opens firstNewStream
			Expect(err).ToNot(HaveOccurred())
			Expect(m.DeleteStream(1)).To(Succeed())
			err = m.DeleteStream(1)
			Expect(err).To(HaveOccurred())
			Expect(err.(streamError).TestError()).To(MatchError("tried to delete unknown outgoing stream 1"))
		})

		It("closes all streams when CloseWithError is called", func() {
			str1, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str2, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			testErr := errors.New("test err")
			m.CloseWithError(testErr)
			Expect(str1.closed).To(BeTrue())
			Expect(str1.closeErr).To(MatchError(testErr))
			Expect(str2.closed).To(BeTrue())
			Expect(str2.closeErr).To(MatchError(testErr))
		})

		It("updates the send window", func() {
			str1, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			str2, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			m.UpdateSendWindow(1337)
			Expect(str1.sendWindow).To(BeEquivalentTo(1337))
			Expect(str2.sendWindow).To(BeEquivalentTo(1337))
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
				Expect(str.num).To(Equal(protocol.StreamNum(1)))
				close(done)
			}()
			waitForEnqueued(1)

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
			waitForEnqueued(1)

			cancel()
			Eventually(done).Should(BeClosed())

			// make sure that the next stream opened is stream 1
			m.SetMaxStream(1000)
			str, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str.num).To(Equal(protocol.StreamNum(1)))
		})

		It("opens streams in the right order", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.num).To(Equal(protocol.StreamNum(1)))
				close(done1)
			}()
			waitForEnqueued(1)

			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.num).To(Equal(protocol.StreamNum(2)))
				close(done2)
			}()
			waitForEnqueued(2)

			m.SetMaxStream(1)
			Eventually(done1).Should(BeClosed())
			Consistently(done2).ShouldNot(BeClosed())
			m.SetMaxStream(2)
			Eventually(done2).Should(BeClosed())
		})

		It("opens streams in the right order, when one of the contexts is canceled", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).AnyTimes()
			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.num).To(Equal(protocol.StreamNum(1)))
				close(done1)
			}()
			waitForEnqueued(1)

			done2 := make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(ctx)
				Expect(err).To(MatchError(context.Canceled))
				close(done2)
			}()
			waitForEnqueued(2)

			done3 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				str, err := m.OpenStreamSync(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.num).To(Equal(protocol.StreamNum(2)))
				close(done3)
			}()
			waitForEnqueued(3)

			cancel()
			Eventually(done2).Should(BeClosed())
			m.SetMaxStream(1000)
			Eventually(done1).Should(BeClosed())
			Eventually(done3).Should(BeClosed())
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
			waitForEnqueued(2)
			go func() {
				defer GinkgoRecover()
				_, err := m.OpenStreamSync(context.Background())
				Expect(err).To(MatchError("test done"))
				done <- struct{}{}
			}()
			waitForEnqueued(3)

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
				Expect(str.num).To(Equal(protocol.StreamNum(1)))
				close(openedSync)
			}()
			waitForEnqueued(1)

			start := make(chan struct{})
			openend := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				var hasStarted bool
				for {
					str, err := m.OpenStream()
					if err == nil {
						Expect(str.num).To(Equal(protocol.StreamNum(2)))
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
			Expect(str.num).To(Equal(protocol.StreamNum(2)))
		})

		It("queues a STREAMS_BLOCKED frame if no stream can be opened", func() {
			m.SetMaxStream(6)
			// open the 6 allowed streams
			for i := 0; i < 6; i++ {
				_, err := m.OpenStream()
				Expect(err).ToNot(HaveOccurred())
			}

			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				bf := f.(*wire.StreamsBlockedFrame)
				Expect(bf.Type).To(BeEquivalentTo(streamType))
				Expect(bf.StreamLimit).To(BeEquivalentTo(6))
			})
			_, err := m.OpenStream()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(errTooManyOpenStreams.Error()))
		})

		It("only sends one STREAMS_BLOCKED frame for one stream ID", func() {
			m.SetMaxStream(1)
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeEquivalentTo(1))
			})
			_, err := m.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			// try to open a stream twice, but expect only one STREAMS_BLOCKED to be sent
			_, err = m.OpenStream()
			expectTooManyStreamsError(err)
			_, err = m.OpenStream()
			expectTooManyStreamsError(err)
		})

		It("queues a STREAMS_BLOCKED frame when there more streams waiting for OpenStreamSync than MAX_STREAMS allows", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeEquivalentTo(0))
			})
			done := make(chan struct{}, 2)
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
			waitForEnqueued(2)

			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				Expect(f.(*wire.StreamsBlockedFrame).StreamLimit).To(BeEquivalentTo(1))
			})
			m.SetMaxStream(1)
			Eventually(done).Should(Receive())
			Consistently(done).ShouldNot(Receive())
			m.SetMaxStream(2)
			Eventually(done).Should(Receive())
		})
	})

	Context("randomized tests", func() {
		It("opens streams", func() {
			rand.Seed(uint64(GinkgoRandomSeed()))
			const n = 100
			fmt.Fprintf(GinkgoWriter, "Opening %d streams concurrently.\n", n)

			var blockedAt []protocol.StreamNum
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				blockedAt = append(blockedAt, f.(*wire.StreamsBlockedFrame).StreamLimit)
			}).AnyTimes()
			done := make(map[int]chan struct{})
			for i := 1; i <= n; i++ {
				c := make(chan struct{})
				done[i] = c

				go func(doneChan chan struct{}, id protocol.StreamNum) {
					defer GinkgoRecover()
					defer close(doneChan)
					str, err := m.OpenStreamSync(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(str.num).To(Equal(id))
				}(c, protocol.StreamNum(i))
				waitForEnqueued(i)
			}

			var limit int
			limits := []protocol.StreamNum{0}
			for limit < n {
				limit += rand.Intn(n/5) + 1
				if limit <= n {
					limits = append(limits, protocol.StreamNum(limit))
				}
				fmt.Fprintf(GinkgoWriter, "Setting stream limit to %d.\n", limit)
				m.SetMaxStream(protocol.StreamNum(limit))
				for i := 1; i <= n; i++ {
					if i <= limit {
						Eventually(done[i]).Should(BeClosed())
					} else {
						Expect(done[i]).ToNot(BeClosed())
					}
				}
				str, err := m.OpenStream()
				if limit <= n {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal(errTooManyOpenStreams.Error()))
				} else {
					Expect(str.num).To(Equal(protocol.StreamNum(n + 1)))
				}
			}
			Expect(blockedAt).To(Equal(limits))
		})

		It("opens streams, when some of them are getting canceled", func() {
			rand.Seed(uint64(GinkgoRandomSeed()))
			const n = 100
			fmt.Fprintf(GinkgoWriter, "Opening %d streams concurrently.\n", n)

			var blockedAt []protocol.StreamNum
			mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
				blockedAt = append(blockedAt, f.(*wire.StreamsBlockedFrame).StreamLimit)
			}).AnyTimes()

			ctx, cancel := context.WithCancel(context.Background())
			streamsToCancel := make(map[protocol.StreamNum]struct{}) // used as a set
			for i := 0; i < 10; i++ {
				id := protocol.StreamNum(rand.Intn(n) + 1)
				fmt.Fprintf(GinkgoWriter, "Canceling stream %d.\n", id)
				streamsToCancel[id] = struct{}{}
			}

			streamWillBeCanceled := func(id protocol.StreamNum) bool {
				_, ok := streamsToCancel[id]
				return ok
			}

			var streamIDs []int
			var mutex sync.Mutex
			done := make(map[int]chan struct{})
			for i := 1; i <= n; i++ {
				c := make(chan struct{})
				done[i] = c

				go func(doneChan chan struct{}, id protocol.StreamNum) {
					defer GinkgoRecover()
					defer close(doneChan)
					cont := context.Background()
					if streamWillBeCanceled(id) {
						cont = ctx
					}
					str, err := m.OpenStreamSync(cont)
					if streamWillBeCanceled(id) {
						Expect(err).To(MatchError(context.Canceled))
						return
					}
					Expect(err).ToNot(HaveOccurred())
					mutex.Lock()
					streamIDs = append(streamIDs, int(str.num))
					mutex.Unlock()
				}(c, protocol.StreamNum(i))
				waitForEnqueued(i)
			}

			cancel()
			for id := range streamsToCancel {
				Eventually(done[int(id)]).Should(BeClosed())
			}
			var limit int
			numStreams := n - len(streamsToCancel)
			var limits []protocol.StreamNum
			for limit < numStreams {
				limits = append(limits, protocol.StreamNum(limit))
				limit += rand.Intn(n/5) + 1
				fmt.Fprintf(GinkgoWriter, "Setting stream limit to %d.\n", limit)
				m.SetMaxStream(protocol.StreamNum(limit))
				l := limit
				if l > numStreams {
					l = numStreams
				}
				Eventually(func() int {
					mutex.Lock()
					defer mutex.Unlock()
					return len(streamIDs)
				}).Should(Equal(l))
				// check that all stream IDs were used
				Expect(streamIDs).To(HaveLen(l))
				sort.Ints(streamIDs)
				for i := 0; i < l; i++ {
					Expect(streamIDs[i]).To(Equal(i + 1))
				}
			}
			Expect(blockedAt).To(Equal(limits))
		})
	})
})
