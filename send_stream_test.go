package quic

import (
	"bytes"
	"errors"
	"io"
	mrand "math/rand"
	"runtime"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Send Stream", func() {
	const streamID protocol.StreamID = 1337

	var (
		str            *sendStream
		strWithTimeout io.Writer // str wrapped with gbytes.TimeoutWriter
		mockFC         *mocks.MockStreamFlowController
		mockSender     *MockStreamSender
	)

	BeforeEach(func() {
		mockSender = NewMockStreamSender(mockCtrl)
		mockFC = mocks.NewMockStreamFlowController(mockCtrl)
		str = newSendStream(streamID, mockSender, mockFC)

		timeout := scaleDuration(250 * time.Millisecond)
		strWithTimeout = gbytes.TimeoutWriter(str, timeout)
	})

	expectedFrameHeaderLen := func(offset protocol.ByteCount) protocol.ByteCount {
		return (&wire.StreamFrame{
			StreamID:       streamID,
			Offset:         offset,
			DataLenPresent: true,
		}).Length(protocol.VersionWhatever)
	}

	waitForWrite := func() {
		EventuallyWithOffset(0, func() bool {
			str.mutex.Lock()
			hasData := str.dataForWriting != nil || str.nextFrame != nil
			str.mutex.Unlock()
			return hasData
		}).Should(BeTrue())
	}

	getDataAtOffset := func(offset, length protocol.ByteCount) []byte {
		b := make([]byte, length)
		for i := protocol.ByteCount(0); i < length; i++ {
			b[i] = uint8(offset + i)
		}
		return b
	}

	getData := func(length protocol.ByteCount) []byte {
		return getDataAtOffset(0, length)
	}

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	Context("writing", func() {
		It("writes and gets all data at once", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				mockSender.EXPECT().onHasStreamData(streamID)
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
			}()
			waitForWrite()
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			frame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("foobar")))
			Expect(f.Fin).To(BeFalse())
			Expect(f.Offset).To(BeZero())
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("writes and gets data in two turns", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				mockSender.EXPECT().onHasStreamData(streamID)
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			waitForWrite()
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3)).Times(2)
			frame, _ := str.popStreamFrame(expectedFrameHeaderLen(0)+3, protocol.Version1)
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.Offset).To(BeZero())
			Expect(f.Fin).To(BeFalse())
			Expect(f.Data).To(Equal([]byte("foo")))
			Expect(f.DataLenPresent).To(BeTrue())
			frame, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.Fin).To(BeFalse())
			Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.popStreamFrame(1000, protocol.Version1)).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("bundles small writes", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				mockSender.EXPECT().onHasStreamData(streamID).Times(2)
				n, err := strWithTimeout.Write([]byte("foo"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				n, err = strWithTimeout.Write([]byte("bar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				close(done)
			}()
			Eventually(done).Should(BeClosed()) // both Write calls returned without any data having been dequeued yet
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			frame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.Offset).To(BeZero())
			Expect(f.Fin).To(BeFalse())
			Expect(f.Data).To(Equal([]byte("foobar")))
		})

		It("writes and gets data in multiple turns, for large writes", func() {
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(5)
			var totalBytesSent protocol.ByteCount
			mockFC.EXPECT().AddBytesSent(gomock.Any()).Do(func(l protocol.ByteCount) { totalBytesSent += l }).Times(5)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				mockSender.EXPECT().onHasStreamData(streamID)
				n, err := strWithTimeout.Write(getData(5000))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(5000))
				close(done)
			}()
			waitForWrite()
			for i := 0; i < 5; i++ {
				frame, _ := str.popStreamFrame(1100, protocol.Version1)
				f := frame.Frame.(*wire.StreamFrame)
				Expect(f.Offset).To(BeNumerically("~", 1100*i, 10*i))
				Expect(f.Fin).To(BeFalse())
				Expect(f.Data).To(Equal(getDataAtOffset(f.Offset, f.DataLen())))
				Expect(f.DataLenPresent).To(BeTrue())
			}
			Expect(totalBytesSent).To(Equal(protocol.ByteCount(5000)))
			Eventually(done).Should(BeClosed())
		})

		It("unblocks Write as soon as a STREAM frame can be buffered", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				mockSender.EXPECT().onHasStreamData(streamID)
				_, err := strWithTimeout.Write(getData(protocol.MaxPacketBufferSize + 3))
				Expect(err).ToNot(HaveOccurred())
			}()
			waitForWrite()
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(2))
			frame, hasMoreData := str.popStreamFrame(expectedFrameHeaderLen(0)+2, protocol.Version1)
			Expect(hasMoreData).To(BeTrue())
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.DataLen()).To(Equal(protocol.ByteCount(2)))
			Consistently(done).ShouldNot(BeClosed())
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(1))
			frame, hasMoreData = str.popStreamFrame(expectedFrameHeaderLen(1)+1, protocol.Version1)
			Expect(hasMoreData).To(BeTrue())
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.DataLen()).To(Equal(protocol.ByteCount(1)))
			Eventually(done).Should(BeClosed())
		})

		It("only unblocks Write once a previously buffered STREAM frame has been fully dequeued", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			_, err := strWithTimeout.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				mockSender.EXPECT().onHasStreamData(streamID)
				_, err := str.Write(getData(protocol.MaxPacketBufferSize))
				Expect(err).ToNot(HaveOccurred())
			}()
			waitForWrite()
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(2))
			frame, hasMoreData := str.popStreamFrame(expectedFrameHeaderLen(0)+2, protocol.Version1)
			Expect(hasMoreData).To(BeTrue())
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("fo")))
			Consistently(done).ShouldNot(BeClosed())
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(4))
			frame, hasMoreData = str.popStreamFrame(expectedFrameHeaderLen(2)+4, protocol.Version1)
			Expect(hasMoreData).To(BeTrue())
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("obar")))
			Eventually(done).Should(BeClosed())
		})

		It("popStreamFrame returns nil if no data is available", func() {
			frame, hasMoreData := str.popStreamFrame(1000, protocol.Version1)
			Expect(frame).To(BeNil())
			Expect(hasMoreData).To(BeFalse())
		})

		It("says if it has more data for writing", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				mockSender.EXPECT().onHasStreamData(streamID)
				n, err := strWithTimeout.Write(bytes.Repeat([]byte{0}, 100))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(100))
			}()
			waitForWrite()
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
			mockFC.EXPECT().AddBytesSent(gomock.Any()).Times(2)
			frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			Expect(frame.Frame.(*wire.StreamFrame).Fin).To(BeFalse())
			Expect(hasMoreData).To(BeTrue())
			frame, hasMoreData = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			Expect(frame.Frame.(*wire.StreamFrame).Fin).To(BeFalse())
			Expect(hasMoreData).To(BeFalse())
			frame, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(frame).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("copies the slice while writing", func() {
			frameHeaderSize := protocol.ByteCount(4)
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(1))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(2))
			s := []byte("foo")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				mockSender.EXPECT().onHasStreamData(streamID)
				n, err := strWithTimeout.Write(s)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
			}()
			waitForWrite()
			frame, _ := str.popStreamFrame(frameHeaderSize+1, protocol.Version1)
			f := frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("f")))
			frame, _ = str.popStreamFrame(100, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.Data).To(Equal([]byte("oo")))
			s[1] = 'e'
			Expect(f.Data).To(Equal([]byte("oo")))
			Eventually(done).Should(BeClosed())
		})

		It("returns when given a nil input", func() {
			n, err := strWithTimeout.Write(nil)
			Expect(n).To(BeZero())
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns when given an empty slice", func() {
			n, err := strWithTimeout.Write([]byte(""))
			Expect(n).To(BeZero())
			Expect(err).ToNot(HaveOccurred())
		})

		It("cancels the context when Close is called", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			Expect(str.Context().Done()).ToNot(BeClosed())
			Expect(str.Close()).To(Succeed())
			Expect(str.Context().Done()).To(BeClosed())
		})

		Context("flow control blocking", func() {
			It("queues a BLOCKED frame if the stream is flow control blocked", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(0))
				mockFC.EXPECT().IsNewlyBlocked().Return(true, protocol.ByteCount(12))
				mockSender.EXPECT().queueControlFrame(&wire.StreamDataBlockedFrame{
					StreamID:          streamID,
					MaximumStreamData: 12,
				})
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					mockSender.EXPECT().onHasStreamData(streamID)
					_, err := str.Write([]byte("foobar"))
					Expect(err).ToNot(HaveOccurred())
				}()
				waitForWrite()
				f, hasMoreData := str.popStreamFrame(1000, protocol.Version1)
				Expect(f).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
				// make the Write go routine return
				str.closeForShutdown(nil)
				Eventually(done).Should(BeClosed())
			})

			It("says that it doesn't have any more data, when it is flow control blocked", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					mockSender.EXPECT().onHasStreamData(streamID)
					_, err := str.Write([]byte("foobar"))
					Expect(err).ToNot(HaveOccurred())
				}()
				waitForWrite()

				// first pop a STREAM frame of the maximum size allowed by flow control
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(3))
				mockFC.EXPECT().AddBytesSent(protocol.ByteCount(3))
				f, hasMoreData := str.popStreamFrame(expectedFrameHeaderLen(0)+3, protocol.Version1)
				Expect(f).ToNot(BeNil())
				Expect(hasMoreData).To(BeTrue())

				// try to pop again, this time noticing that we're blocked
				mockFC.EXPECT().SendWindowSize()
				// don't use offset 3 here, to make sure the BLOCKED frame contains the number returned by the flow controller
				mockFC.EXPECT().IsNewlyBlocked().Return(true, protocol.ByteCount(10))
				mockSender.EXPECT().queueControlFrame(&wire.StreamDataBlockedFrame{
					StreamID:          streamID,
					MaximumStreamData: 10,
				})
				f, hasMoreData = str.popStreamFrame(1000, protocol.Version1)
				Expect(f).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
				// make the Write go routine return
				str.closeForShutdown(nil)
				Eventually(done).Should(BeClosed())
			})
		})

		Context("deadlines", func() {
			It("returns an error when Write is called after the deadline", func() {
				str.SetWriteDeadline(time.Now().Add(-time.Second))
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
			})

			It("unblocks after the deadline", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				n, err := strWithTimeout.Write(getData(5000))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(20*time.Millisecond)))
			})

			It("unblocks when the deadline is changed to the past", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				str.SetWriteDeadline(time.Now().Add(time.Hour))
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := str.Write(getData(5000))
					Expect(err).To(MatchError(errDeadline))
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				str.SetWriteDeadline(time.Now().Add(-time.Hour))
				Eventually(done).Should(BeClosed())
			})

			It("returns the number of bytes written, when the deadline expires", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).AnyTimes()
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				var n int
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(writeReturned)
					mockSender.EXPECT().onHasStreamData(streamID)
					var err error
					n, err = strWithTimeout.Write(getData(5000))
					Expect(err).To(MatchError(errDeadline))
					Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(20*time.Millisecond)))
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				Expect(hasMoreData).To(BeTrue())
				Eventually(writeReturned, scaleDuration(80*time.Millisecond)).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.Frame.(*wire.StreamFrame).DataLen()))
			})

			It("doesn't pop any data after the deadline expired", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).AnyTimes()
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(writeReturned)
					mockSender.EXPECT().onHasStreamData(streamID)
					_, err := strWithTimeout.Write(getData(5000))
					Expect(err).To(MatchError(errDeadline))
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				Expect(hasMoreData).To(BeTrue())
				Eventually(writeReturned, scaleDuration(80*time.Millisecond)).Should(BeClosed())
				frame, hasMoreData = str.popStreamFrame(50, protocol.Version1)
				Expect(frame).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
			})

			It("doesn't unblock if the deadline is changed before the first one expires", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				deadline1 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(100 * time.Millisecond))
				str.SetWriteDeadline(deadline1)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(20 * time.Millisecond))
					str.SetWriteDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline1))
					close(done)
				}()
				runtime.Gosched()
				n, err := strWithTimeout.Write(getData(5000))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(20*time.Millisecond)))
				Eventually(done).Should(BeClosed())
			})

			It("unblocks earlier, when a new deadline is set", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				deadline1 := time.Now().Add(scaleDuration(200 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(10 * time.Millisecond))
					str.SetWriteDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline2))
					close(done)
				}()
				str.SetWriteDeadline(deadline1)
				runtime.Gosched()
				_, err := strWithTimeout.Write(getData(5000))
				Expect(err).To(MatchError(errDeadline))
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(20*time.Millisecond)))
				Eventually(done).Should(BeClosed())
			})

			It("doesn't unblock if the deadline is removed", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				deadlineUnset := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(20 * time.Millisecond))
					str.SetWriteDeadline(time.Time{})
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline))
					close(deadlineUnset)
				}()
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(getData(5000))
					Expect(err).To(MatchError("test done"))
					close(done)
				}()
				runtime.Gosched()
				Eventually(deadlineUnset).Should(BeClosed())
				Consistently(done, scaleDuration(100*time.Millisecond)).ShouldNot(BeClosed())
				// make the go routine return
				str.closeForShutdown(errors.New("test done"))
				Eventually(done).Should(BeClosed())
			})
		})

		Context("closing", func() {
			It("doesn't allow writes after it has been closed", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				str.Close()
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError("write on closed stream 1337"))
			})

			It("allows FIN", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				str.Close()
				frame, hasMoreData := str.popStreamFrame(1000, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				f := frame.Frame.(*wire.StreamFrame)
				Expect(f.Data).To(BeEmpty())
				Expect(f.Fin).To(BeTrue())
				Expect(f.DataLenPresent).To(BeTrue())
				Expect(hasMoreData).To(BeFalse())
			})

			It("doesn't send a FIN when there's still data", func() {
				const frameHeaderLen protocol.ByteCount = 4
				mockSender.EXPECT().onHasStreamData(streamID).Times(2)
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).Times(2)
				mockFC.EXPECT().AddBytesSent(gomock.Any()).Times(2)
				frame, _ := str.popStreamFrame(3+frameHeaderLen, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				f := frame.Frame.(*wire.StreamFrame)
				Expect(f.Data).To(Equal([]byte("foo")))
				Expect(f.Fin).To(BeFalse())
				frame, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
				f = frame.Frame.(*wire.StreamFrame)
				Expect(f.Data).To(Equal([]byte("bar")))
				Expect(f.Fin).To(BeTrue())
			})

			It("doesn't send a FIN when there's still data, for long writes", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					mockSender.EXPECT().onHasStreamData(streamID)
					_, err := strWithTimeout.Write(getData(5000))
					Expect(err).ToNot(HaveOccurred())
					mockSender.EXPECT().onHasStreamData(streamID)
					Expect(str.Close()).To(Succeed())
				}()
				waitForWrite()
				for i := 1; i <= 5; i++ {
					mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
					mockFC.EXPECT().AddBytesSent(gomock.Any())
					if i == 5 {
						Eventually(done).Should(BeClosed())
					}
					frame, _ := str.popStreamFrame(1100, protocol.Version1)
					Expect(frame).ToNot(BeNil())
					f := frame.Frame.(*wire.StreamFrame)
					Expect(f.Data).To(Equal(getDataAtOffset(f.Offset, f.DataLen())))
					Expect(f.Fin).To(Equal(i == 5)) // the last frame should have the FIN bit set
				}
			})

			It("doesn't allow FIN after it is closed for shutdown", func() {
				str.closeForShutdown(errors.New("test"))
				f, hasMoreData := str.popStreamFrame(1000, protocol.Version1)
				Expect(f).To(BeNil())
				Expect(hasMoreData).To(BeFalse())

				Expect(str.Close()).To(Succeed())
				f, hasMoreData = str.popStreamFrame(1000, protocol.Version1)
				Expect(f).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
			})

			It("doesn't allow FIN twice", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				str.Close()
				frame, _ := str.popStreamFrame(1000, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				f := frame.Frame.(*wire.StreamFrame)
				Expect(f.Data).To(BeEmpty())
				Expect(f.Fin).To(BeTrue())
				frame, hasMoreData := str.popStreamFrame(1000, protocol.Version1)
				Expect(frame).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
			})
		})

		Context("closing for shutdown", func() {
			testErr := errors.New("test")

			It("returns errors when the stream is cancelled", func() {
				str.closeForShutdown(testErr)
				n, err := strWithTimeout.Write([]byte("foo"))
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("doesn't get data for writing if an error occurred", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				mockSender.EXPECT().onHasStreamData(streamID)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(getData(5000))
					Expect(err).To(MatchError(testErr))
					close(done)
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1) // get a STREAM frame containing some data, but not all
				Expect(frame).ToNot(BeNil())
				Expect(hasMoreData).To(BeTrue())
				str.closeForShutdown(testErr)
				frame, hasMoreData = str.popStreamFrame(1000, protocol.Version1)
				Expect(frame).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
				Eventually(done).Should(BeClosed())
			})

			It("cancels the context", func() {
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.closeForShutdown(testErr)
				Expect(str.Context().Done()).To(BeClosed())
			})
		})
	})

	Context("handling MAX_STREAM_DATA frames", func() {
		It("informs the flow controller", func() {
			mockFC.EXPECT().UpdateSendWindow(protocol.ByteCount(0x1337))
			str.updateSendWindow(0x1337)
		})

		It("says when it has data for sending", func() {
			mockFC.EXPECT().UpdateSendWindow(gomock.Any())
			mockSender.EXPECT().onHasStreamData(streamID)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			waitForWrite()
			mockSender.EXPECT().onHasStreamData(streamID)
			str.updateSendWindow(42)
			// make sure the Write go routine returns
			str.closeForShutdown(nil)
			Eventually(done).Should(BeClosed())
		})
	})

	Context("stream cancellations", func() {
		Context("canceling writing", func() {
			It("queues a RESET_STREAM frame", func() {
				gomock.InOrder(
					mockSender.EXPECT().queueControlFrame(&wire.ResetStreamFrame{
						StreamID:  streamID,
						FinalSize: 1234,
						ErrorCode: 9876,
					}),
					mockSender.EXPECT().onStreamCompleted(streamID),
				)
				str.writeOffset = 1234
				str.CancelWrite(9876)
			})

			// This test is inherently racy, as it tests a concurrent call to Write() and CancelRead().
			// A single successful run of this test therefore doesn't mean a lot,
			// for reliable results it has to be run many times.
			It("returns a nil error when the whole slice has been sent out", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any()).MaxTimes(1)
				mockSender.EXPECT().onHasStreamData(streamID).MaxTimes(1)
				mockSender.EXPECT().onStreamCompleted(streamID).MaxTimes(1)
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).MaxTimes(1)
				mockFC.EXPECT().AddBytesSent(gomock.Any()).MaxTimes(1)
				errChan := make(chan error)
				go func() {
					defer GinkgoRecover()
					n, err := strWithTimeout.Write(getData(100))
					if n == 0 {
						errChan <- nil
						return
					}
					errChan <- err
				}()

				runtime.Gosched()
				go str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
				go str.CancelWrite(1234)
				Eventually(errChan).Should(Receive(Not(HaveOccurred())))
			})

			It("unblocks Write", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onHasStreamData(streamID)
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				writeReturned := make(chan struct{})
				var n int
				go func() {
					defer GinkgoRecover()
					var err error
					n, err = strWithTimeout.Write(getData(5000))
					Expect(err).To(Equal(&StreamError{
						StreamID:  streamID,
						ErrorCode: 1234,
						Remote:    false,
					}))
					close(writeReturned)
				}()
				waitForWrite()
				frame, _ := str.popStreamFrame(50, protocol.Version1)
				Expect(frame).ToNot(BeNil())
				mockSender.EXPECT().onStreamCompleted(streamID)
				str.CancelWrite(1234)
				Eventually(writeReturned).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.Frame.(*wire.StreamFrame).DataLen()))
			})

			It("doesn't pop STREAM frames after being canceled", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onHasStreamData(streamID)
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					strWithTimeout.Write(getData(100))
					close(writeReturned)
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
				Expect(hasMoreData).To(BeTrue())
				Expect(frame).ToNot(BeNil())
				mockSender.EXPECT().onStreamCompleted(streamID)
				str.CancelWrite(1234)
				frame, hasMoreData = str.popStreamFrame(10, protocol.Version1)
				Expect(frame).To(BeNil())
				Expect(hasMoreData).To(BeFalse())
				Eventually(writeReturned).Should(BeClosed())
			})

			It("doesn't pop STREAM frames after being canceled, for large writes", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onHasStreamData(streamID)
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(getData(5000))
					Expect(err).To(Equal(&StreamError{
						StreamID:  streamID,
						ErrorCode: 1234,
						Remote:    false,
					}))
					close(writeReturned)
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
				Expect(hasMoreData).To(BeTrue())
				Expect(frame).ToNot(BeNil())
				mockSender.EXPECT().onStreamCompleted(streamID)
				str.CancelWrite(1234)
				frame, hasMoreData = str.popStreamFrame(10, protocol.Version1)
				Expect(hasMoreData).To(BeFalse())
				Expect(frame).To(BeNil())
				Eventually(writeReturned).Should(BeClosed())
			})

			It("ignores acknowledgements for STREAM frames after it was cancelled", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onHasStreamData(streamID)
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					strWithTimeout.Write(getData(100))
					close(writeReturned)
				}()
				waitForWrite()
				frame, hasMoreData := str.popStreamFrame(50, protocol.Version1)
				Expect(hasMoreData).To(BeTrue())
				Expect(frame).ToNot(BeNil())
				mockSender.EXPECT().onStreamCompleted(streamID)
				str.CancelWrite(1234)
				frame.OnAcked(frame.Frame)
			})

			It("cancels the context", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.CancelWrite(1234)
				Expect(str.Context().Done()).To(BeClosed())
			})

			It("doesn't allow further calls to Write", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				str.CancelWrite(1234)
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(&StreamError{
					StreamID:  streamID,
					ErrorCode: 1234,
					Remote:    false,
				}))
			})

			It("only cancels once", func() {
				mockSender.EXPECT().queueControlFrame(&wire.ResetStreamFrame{StreamID: streamID, ErrorCode: 1234})
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				str.CancelWrite(1234)
				str.CancelWrite(4321)
			})

			It("queues a RESET_STREAM frame, even if the stream was already closed", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				mockSender.EXPECT().queueControlFrame(gomock.Any()).Do(func(f wire.Frame) {
					Expect(f).To(BeAssignableToTypeOf(&wire.ResetStreamFrame{}))
				})
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				Expect(str.Close()).To(Succeed())
				// don't EXPECT any calls to queueControlFrame
				str.CancelWrite(123)
			})
		})

		Context("receiving STOP_SENDING frames", func() {
			It("queues a RESET_STREAM frames, and copies the error code from the STOP_SENDING frame", func() {
				mockSender.EXPECT().queueControlFrame(&wire.ResetStreamFrame{
					StreamID:  streamID,
					ErrorCode: 101,
				})
				mockSender.EXPECT().onStreamCompleted(gomock.Any())

				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 101,
				})
			})

			It("unblocks Write", func() {
				mockSender.EXPECT().onHasStreamData(streamID)
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := str.Write(getData(5000))
					Expect(err).To(Equal(&StreamError{
						StreamID:  streamID,
						ErrorCode: 123,
						Remote:    true,
					}))
					close(done)
				}()
				waitForWrite()
				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 123,
				})
				Eventually(done).Should(BeClosed())
			})

			It("doesn't allow further calls to Write", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockSender.EXPECT().onStreamCompleted(gomock.Any())
				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 123,
				})
				_, err := str.Write([]byte("foobar"))
				Expect(err).To(Equal(&StreamError{
					StreamID:  streamID,
					ErrorCode: 123,
					Remote:    true,
				}))
			})
		})
	})

	Context("retransmissions", func() {
		It("queues and retrieves frames", func() {
			str.numOutstandingFrames = 1
			f := &wire.StreamFrame{
				Data:           []byte("foobar"),
				Offset:         0x42,
				DataLenPresent: false,
			}
			mockSender.EXPECT().onHasStreamData(streamID)
			str.queueRetransmission(f)
			frame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x42)))
			Expect(f.Data).To(Equal([]byte("foobar")))
			Expect(f.DataLenPresent).To(BeTrue())
		})

		It("splits a retransmission", func() {
			str.numOutstandingFrames = 1
			sf := &wire.StreamFrame{
				Data:           []byte("foobar"),
				Offset:         0x42,
				DataLenPresent: false,
			}
			mockSender.EXPECT().onHasStreamData(streamID)
			str.queueRetransmission(sf)
			frame, hasMoreData := str.popStreamFrame(sf.Length(protocol.Version1)-3, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			f := frame.Frame.(*wire.StreamFrame)
			Expect(hasMoreData).To(BeTrue())
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x42)))
			Expect(f.Data).To(Equal([]byte("foo")))
			Expect(f.DataLenPresent).To(BeTrue())
			frame, _ = str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			f = frame.Frame.(*wire.StreamFrame)
			Expect(f.Offset).To(Equal(protocol.ByteCount(0x45)))
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.DataLenPresent).To(BeTrue())
		})

		It("returns nil if the size is too small", func() {
			str.numOutstandingFrames = 1
			f := &wire.StreamFrame{
				Data:           []byte("foobar"),
				Offset:         0x42,
				DataLenPresent: false,
			}
			mockSender.EXPECT().onHasStreamData(streamID)
			str.queueRetransmission(f)
			frame, hasMoreData := str.popStreamFrame(2, protocol.Version1)
			Expect(hasMoreData).To(BeTrue())
			Expect(frame).To(BeNil())
		})

		It("queues lost STREAM frames", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			waitForWrite()
			frame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Eventually(done).Should(BeClosed())
			Expect(frame).ToNot(BeNil())
			Expect(frame.Frame.(*wire.StreamFrame).Data).To(Equal([]byte("foobar")))

			// now lose the frame
			mockSender.EXPECT().onHasStreamData(streamID)
			frame.OnLost(frame.Frame)
			newFrame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(newFrame).ToNot(BeNil())
			Expect(newFrame.Frame.(*wire.StreamFrame).Data).To(Equal([]byte("foobar")))
		})

		It("doesn't queue retransmissions for a stream that was canceled", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			waitForWrite()
			f, _ := str.popStreamFrame(100, protocol.Version1)
			Eventually(done).Should(BeClosed())
			Expect(f).ToNot(BeNil())
			gomock.InOrder(
				mockSender.EXPECT().queueControlFrame(gomock.Any()),
				mockSender.EXPECT().onStreamCompleted(streamID),
			)
			str.CancelWrite(9876)
			// don't EXPECT any calls to onHasStreamData
			f.OnLost(f.Frame)
			Expect(str.retransmissionQueue).To(BeEmpty())
		})
	})

	Context("determining when a stream is completed", func() {
		BeforeEach(func() {
			mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).AnyTimes()
			mockFC.EXPECT().AddBytesSent(gomock.Any()).AnyTimes()
		})

		It("says when a stream is completed", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := strWithTimeout.Write(make([]byte, 100))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			waitForWrite()

			// get a bunch of small frames (max. 20 bytes)
			var frames []ackhandler.Frame
			for {
				frame, hasMoreData := str.popStreamFrame(20, protocol.Version1)
				if frame == nil {
					continue
				}
				frames = append(frames, *frame)
				if !hasMoreData {
					break
				}
			}
			Eventually(done).Should(BeClosed())

			// Acknowledge all frames.
			// We don't expect the stream to be completed, since we still need to send the FIN.
			for _, f := range frames {
				f.OnAcked(f.Frame)
			}

			// Now close the stream and acknowledge the FIN.
			mockSender.EXPECT().onHasStreamData(streamID)
			Expect(str.Close()).To(Succeed())
			frame, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(frame).ToNot(BeNil())
			mockSender.EXPECT().onStreamCompleted(streamID)
			frame.OnAcked(frame.Frame)
		})

		It("says when a stream is completed, if Close() is called before popping the frame", func() {
			mockSender.EXPECT().onHasStreamData(streamID).Times(2)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := strWithTimeout.Write(make([]byte, 100))
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			waitForWrite()
			Eventually(done).Should(BeClosed())
			Expect(str.Close()).To(Succeed())

			frame, hasMoreData := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(hasMoreData).To(BeFalse())
			Expect(frame).ToNot(BeNil())
			Expect(frame.Frame.(*wire.StreamFrame).Fin).To(BeTrue())

			mockSender.EXPECT().onStreamCompleted(streamID)
			frame.OnAcked(frame.Frame)
		})

		It("doesn't say it's completed when there are frames waiting to be retransmitted", func() {
			mockSender.EXPECT().onHasStreamData(streamID)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := strWithTimeout.Write(getData(100))
				Expect(err).ToNot(HaveOccurred())
				mockSender.EXPECT().onHasStreamData(streamID)
				Expect(str.Close()).To(Succeed())
				close(done)
			}()
			waitForWrite()

			// get a bunch of small frames (max. 20 bytes)
			var frames []ackhandler.Frame
			for {
				frame, _ := str.popStreamFrame(20, protocol.Version1)
				if frame == nil {
					continue
				}
				frames = append(frames, *frame)
				if frame.Frame.(*wire.StreamFrame).Fin {
					break
				}
			}
			Eventually(done).Should(BeClosed())

			// lose the first frame, acknowledge all others
			for _, f := range frames[1:] {
				f.OnAcked(f.Frame)
			}
			mockSender.EXPECT().onHasStreamData(streamID)
			frames[0].OnLost(frames[0].Frame)

			// get the retransmission and acknowledge it
			ret, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(ret).ToNot(BeNil())
			mockSender.EXPECT().onStreamCompleted(streamID)
			ret.OnAcked(ret.Frame)
		})

		// This test is kind of an integration test.
		// It writes 4 MB of data, and pops STREAM frames that sometimes are and sometimes aren't limited by flow control.
		// Half of these STREAM frames are then received and their content saved, while the other half is reported lost
		// and has to be retransmitted.
		It("retransmits data until everything has been acknowledged", func() {
			const dataLen = 1 << 22 // 4 MB
			mockSender.EXPECT().onHasStreamData(streamID).AnyTimes()
			mockFC.EXPECT().SendWindowSize().DoAndReturn(func() protocol.ByteCount {
				return protocol.ByteCount(mrand.Intn(500)) + 50
			}).AnyTimes()
			mockFC.EXPECT().AddBytesSent(gomock.Any()).AnyTimes()

			data := make([]byte, dataLen)
			_, err := mrand.Read(data)
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				_, err := str.Write(data)
				Expect(err).ToNot(HaveOccurred())
				str.Close()
			}()

			var completed bool
			mockSender.EXPECT().onStreamCompleted(streamID).Do(func(protocol.StreamID) { completed = true })

			received := make([]byte, dataLen)
			for {
				if completed {
					break
				}
				f, _ := str.popStreamFrame(protocol.ByteCount(mrand.Intn(300)+100), protocol.Version1)
				if f == nil {
					continue
				}
				sf := f.Frame.(*wire.StreamFrame)
				// 50%: acknowledge the frame and save the data
				// 50%: lose the frame
				if mrand.Intn(100) < 50 {
					copy(received[sf.Offset:sf.Offset+sf.DataLen()], sf.Data)
					f.OnAcked(f.Frame)
				} else {
					f.OnLost(f.Frame)
				}
			}
			Expect(received).To(Equal(data))
		})
	})
})
