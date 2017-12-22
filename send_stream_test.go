package quic

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
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
		str = newSendStream(streamID, mockSender, mockFC, protocol.VersionWhatever)

		timeout := scaleDuration(250 * time.Millisecond)
		strWithTimeout = gbytes.TimeoutWriter(str, timeout)
	})

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	Context("writing", func() {
		It("writes and gets all data at once", func() {
			mockSender.EXPECT().scheduleSending()
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			mockFC.EXPECT().IsNewlyBlocked()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())
			var f *wire.StreamFrame
			Eventually(func() *wire.StreamFrame {
				f = str.popStreamFrame(1000)
				return f
			}).ShouldNot(BeNil())
			Expect(f.Data).To(Equal([]byte("foobar")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(BeZero())
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("writes and gets data in two turns", func() {
			mockSender.EXPECT().scheduleSending()
			frameHeaderLen := protocol.ByteCount(4)
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
			mockFC.EXPECT().AddBytesSent(gomock.Any() /* protocol.ByteCount(3)*/).Times(2)
			mockFC.EXPECT().IsNewlyBlocked().Times(2)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())
			var f *wire.StreamFrame
			Eventually(func() *wire.StreamFrame {
				f = str.popStreamFrame(3 + frameHeaderLen)
				return f
			}).ShouldNot(BeNil())
			Expect(f.Data).To(Equal([]byte("foo")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(BeZero())
			Expect(f.DataLenPresent).To(BeTrue())
			f = str.popStreamFrame(100)
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.popStreamFrame(1000)).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("popStreamFrame returns nil if no data is available", func() {
			Expect(str.popStreamFrame(1000)).To(BeNil())
		})

		It("copies the slice while writing", func() {
			mockSender.EXPECT().scheduleSending()
			frameHeaderSize := protocol.ByteCount(4)
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(1))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(2))
			mockFC.EXPECT().IsNewlyBlocked().Times(2)
			s := []byte("foo")
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write(s)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
			}()
			var frame *wire.StreamFrame
			Eventually(func() *wire.StreamFrame { frame = str.popStreamFrame(frameHeaderSize + 1); return frame }).ShouldNot(BeNil())
			Expect(frame.Data).To(Equal([]byte("f")))
			s[1] = 'e'
			f := str.popStreamFrame(100)
			Expect(f).ToNot(BeNil())
			Expect(f.Data).To(Equal([]byte("oo")))
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
			mockSender.EXPECT().scheduleSending()
			Expect(str.Context().Done()).ToNot(BeClosed())
			str.Close()
			Expect(str.Context().Done()).To(BeClosed())
		})

		Context("adding BLOCKED", func() {
			It("queues a BLOCKED frame if the stream is flow control blocked", func() {
				mockSender.EXPECT().scheduleSending()
				mockSender.EXPECT().queueControlFrame(&wire.StreamBlockedFrame{
					StreamID: streamID,
					Offset:   10,
				})
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
				mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
				// don't use offset 6 here, to make sure the BLOCKED frame contains the number returned by the flow controller
				mockFC.EXPECT().IsNewlyBlocked().Return(true, protocol.ByteCount(10))
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := str.Write([]byte("foobar"))
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()
				var f *wire.StreamFrame
				Eventually(func() *wire.StreamFrame {
					f = str.popStreamFrame(1000)
					return f
				}).ShouldNot(BeNil())
				Eventually(done).Should(BeClosed())
			})

			It("doesn't queue a BLOCKED frame if the stream is flow control blocked, but the frame popped has the FIN bit set", func() {
				mockSender.EXPECT().scheduleSending().Times(2) // once for the Write, once for the Close
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
				mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
				// don't EXPECT a call to mockFC.IsNewlyBlocked
				// don't EXPECT a call to mockSender.queueControlFrame
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := str.Write([]byte("foobar"))
					Expect(err).ToNot(HaveOccurred())
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				Expect(str.Close()).To(Succeed())
				var f *wire.StreamFrame
				Eventually(func() *wire.StreamFrame {
					f = str.popStreamFrame(1000)
					return f
				}).ShouldNot(BeNil())
				Expect(f.FinBit).To(BeTrue())
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
				mockSender.EXPECT().scheduleSending()
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(20*time.Millisecond)))
			})

			It("returns the number of bytes written, when the deadline expires", func() {
				mockSender.EXPECT().scheduleSending()
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(10000)).AnyTimes()
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				mockFC.EXPECT().IsNewlyBlocked()
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				var n int
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					var err error
					n, err = strWithTimeout.Write(bytes.Repeat([]byte{0}, 100))
					Expect(err).To(MatchError(errDeadline))
					Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(20*time.Millisecond)))
					close(writeReturned)
				}()
				var frame *wire.StreamFrame
				Eventually(func() *wire.StreamFrame {
					frame = str.popStreamFrame(50)
					return frame
				}).ShouldNot(BeNil())
				Eventually(writeReturned, scaleDuration(80*time.Millisecond)).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.DataLen()))
			})

			It("doesn't pop any data after the deadline expired", func() {
				mockSender.EXPECT().scheduleSending()
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(10000)).AnyTimes()
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				mockFC.EXPECT().IsNewlyBlocked()
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				writeReturned := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(bytes.Repeat([]byte{0}, 100))
					Expect(err).To(MatchError(errDeadline))
					close(writeReturned)
				}()
				var frame *wire.StreamFrame
				Eventually(func() *wire.StreamFrame {
					frame = str.popStreamFrame(50)
					return frame
				}).ShouldNot(BeNil())
				Eventually(writeReturned, scaleDuration(80*time.Millisecond)).Should(BeClosed())
				Expect(str.popStreamFrame(50)).To(BeNil())
			})

			It("doesn't unblock if the deadline is changed before the first one expires", func() {
				mockSender.EXPECT().scheduleSending()
				deadline1 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(100 * time.Millisecond))
				str.SetWriteDeadline(deadline1)
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(20 * time.Millisecond))
					str.SetWriteDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline1))
				}()
				runtime.Gosched()
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(20*time.Millisecond)))
			})

			It("unblocks earlier, when a new deadline is set", func() {
				mockSender.EXPECT().scheduleSending()
				deadline1 := time.Now().Add(scaleDuration(200 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(10 * time.Millisecond))
					str.SetWriteDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline2))
				}()
				str.SetWriteDeadline(deadline1)
				runtime.Gosched()
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(20*time.Millisecond)))
			})
		})

		Context("closing", func() {
			It("doesn't allow writes after it has been closed", func() {
				mockSender.EXPECT().scheduleSending()
				str.Close()
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError("write on closed stream 1337"))
			})

			It("allows FIN", func() {
				mockSender.EXPECT().scheduleSending()
				str.Close()
				f := str.popStreamFrame(1000)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(BeEmpty())
				Expect(f.FinBit).To(BeTrue())
			})

			It("doesn't send a FIN when there's still data", func() {
				mockSender.EXPECT().scheduleSending()
				frameHeaderLen := protocol.ByteCount(4)
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
				mockFC.EXPECT().AddBytesSent(gomock.Any()).Times(2)
				mockFC.EXPECT().IsNewlyBlocked()
				str.dataForWriting = []byte("foobar")
				Expect(str.Close()).To(Succeed())
				f := str.popStreamFrame(3 + frameHeaderLen)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(Equal([]byte("foo")))
				Expect(f.FinBit).To(BeFalse())
				f = str.popStreamFrame(100)
				Expect(f.Data).To(Equal([]byte("bar")))
				Expect(f.FinBit).To(BeTrue())
			})

			It("doesn't allow FIN after an error", func() {
				str.closeForShutdown(errors.New("test"))
				f := str.popStreamFrame(1000)
				Expect(f).To(BeNil())
			})

			It("doesn't allow FIN twice", func() {
				mockSender.EXPECT().scheduleSending()
				str.Close()
				f := str.popStreamFrame(1000)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(BeEmpty())
				Expect(f.FinBit).To(BeTrue())
				Expect(str.popStreamFrame(1000)).To(BeNil())
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
				mockSender.EXPECT().scheduleSending()
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				mockFC.EXPECT().IsNewlyBlocked()
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(bytes.Repeat([]byte{0}, 500))
					Expect(err).To(MatchError(testErr))
					close(done)
				}()
				Eventually(func() *wire.StreamFrame { return str.popStreamFrame(50) }).ShouldNot(BeNil()) // get a STREAM frame containing some data, but not all
				str.closeForShutdown(testErr)
				Expect(str.popStreamFrame(1000)).To(BeNil())
				Eventually(done).Should(BeClosed())
			})

			It("cancels the context", func() {
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.closeForShutdown(testErr)
				Expect(str.Context().Done()).To(BeClosed())
			})
		})
	})

	Context("stream cancelations", func() {
		Context("canceling writing", func() {
			It("queues a RST_STREAM frame", func() {
				mockSender.EXPECT().queueControlFrame(&wire.RstStreamFrame{
					StreamID:   streamID,
					ByteOffset: 1234,
					ErrorCode:  9876,
				})
				str.writeOffset = 1234
				err := str.CancelWrite(9876)
				Expect(err).ToNot(HaveOccurred())
			})

			It("unblocks Write", func() {
				mockSender.EXPECT().scheduleSending()
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				mockFC.EXPECT().IsNewlyBlocked()
				writeReturned := make(chan struct{})
				var n int
				go func() {
					defer GinkgoRecover()
					var err error
					n, err = strWithTimeout.Write(bytes.Repeat([]byte{0}, 100))
					Expect(err).To(MatchError("Write on stream 1337 canceled with error code 1234"))
					close(writeReturned)
				}()
				var frame *wire.StreamFrame
				Eventually(func() *wire.StreamFrame {
					frame = str.popStreamFrame(50)
					return frame
				}).ShouldNot(BeNil())
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				Eventually(writeReturned).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.DataLen()))
			})

			It("cancels the context", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.CancelWrite(1234)
				Expect(str.Context().Done()).To(BeClosed())
			})

			It("doesn't allow further calls to Write", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				_, err = strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError("Write on stream 1337 canceled with error code 1234"))
			})

			It("only cancels once", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				err = str.CancelWrite(4321)
				Expect(err).ToNot(HaveOccurred())
			})

			It("doesn't cancel when the stream was already closed", func() {
				mockSender.EXPECT().scheduleSending()
				err := str.Close()
				Expect(err).ToNot(HaveOccurred())
				err = str.CancelWrite(123)
				Expect(err).To(MatchError("CancelWrite for closed stream 1337"))
			})
		})

		Context("receiving STOP_SENDING frames", func() {
			It("queues a RST_STREAM frames with error code Stopping", func() {
				mockSender.EXPECT().queueControlFrame(&wire.RstStreamFrame{
					StreamID:  streamID,
					ErrorCode: errorCodeStopping,
				})
				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 101,
				})
			})

			It("unblocks Write", func() {
				mockSender.EXPECT().scheduleSending()
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := str.Write([]byte("foobar"))
					Expect(err).To(MatchError("Stream 1337 was reset with error code 123"))
					Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
					Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
					Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(123)))
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 123,
				})
				Eventually(done).Should(BeClosed())
			})

			It("doesn't allow further calls to Write", func() {
				mockSender.EXPECT().queueControlFrame(gomock.Any())
				str.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  streamID,
					ErrorCode: 123,
				})
				_, err := str.Write([]byte("foobar"))
				Expect(err).To(MatchError("Stream 1337 was reset with error code 123"))
				Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
				Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
				Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(123)))
			})
		})
	})

	Context("saying if it is finished", func() {
		It("is finished after it is closed for shutdown", func() {
			str.closeForShutdown(errors.New("testErr"))
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after Close()", func() {
			mockSender.EXPECT().scheduleSending()
			str.Close()
			f := str.popStreamFrame(1000)
			Expect(f.FinBit).To(BeTrue())
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after CancelWrite", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			err := str.CancelWrite(123)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after receiving a STOP_SENDING (and sending a RST_STREAM)", func() {
			mockSender.EXPECT().queueControlFrame(gomock.Any())
			str.handleStopSendingFrame(&wire.StopSendingFrame{StreamID: streamID})
			Expect(str.finished()).To(BeTrue())
		})
	})
})
