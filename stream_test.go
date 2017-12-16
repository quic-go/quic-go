package quic

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strconv"
	"time"

	"os"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("Stream", func() {
	const streamID protocol.StreamID = 1337

	var (
		str            *stream
		strWithTimeout io.ReadWriter // str wrapped with gbytes.Timeout{Reader,Writer}
		onDataCalled   bool

		queuedControlFrames []wire.Frame

		mockFC *mocks.MockStreamFlowController
	)

	// in the tests for the stream deadlines we set a deadline
	// and wait to make an assertion when Read / Write was unblocked
	// on the CIs, the timing is a lot less precise, so scale every duration by this factor
	scaleDuration := func(t time.Duration) time.Duration {
		scaleFactor := 1
		if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
			scaleFactor = f
		}
		Expect(scaleFactor).ToNot(BeZero())
		return time.Duration(scaleFactor) * t
	}

	onData := func() {
		onDataCalled = true
	}

	queueControlFrame := func(f wire.Frame) {
		queuedControlFrames = append(queuedControlFrames, f)
	}

	BeforeEach(func() {
		queuedControlFrames = queuedControlFrames[:0]
		onDataCalled = false
		mockFC = mocks.NewMockStreamFlowController(mockCtrl)
		str = newStream(streamID, onData, queueControlFrame, mockFC, protocol.VersionWhatever)

		timeout := scaleDuration(250 * time.Millisecond)
		strWithTimeout = struct {
			io.Reader
			io.Writer
		}{
			gbytes.TimeoutReader(str, timeout),
			gbytes.TimeoutWriter(str, timeout),
		}
	})

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	Context("reading", func() {
		It("reads a single STREAM frame", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
			frame := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := str.HandleStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("reads a single STREAM frame in multiple goes", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
			frame := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := str.HandleStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 2)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xDE, 0xAD}))
			n, err = strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("reads all data available", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
			frame1 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := wire.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.HandleStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}))
		})

		It("assembles multiple StreamFrames", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
			frame1 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := wire.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.HandleStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("waits until data is available", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
			go func() {
				defer GinkgoRecover()
				frame := wire.StreamFrame{Data: []byte{0xDE, 0xAD}}
				time.Sleep(10 * time.Millisecond)
				err := str.HandleStreamFrame(&frame)
				Expect(err).ToNot(HaveOccurred())
			}()
			b := make([]byte, 2)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
		})

		It("handles StreamFrames in wrong order", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
			frame1 := wire.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			frame2 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			err := str.HandleStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("ignores duplicate StreamFrames", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
			frame1 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0x13, 0x37},
			}
			frame3 := wire.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.HandleStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame3)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("doesn't rejects a StreamFrames with an overlapping data range", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
			frame1 := wire.StreamFrame{
				Offset: 0,
				Data:   []byte("foob"),
			}
			frame2 := wire.StreamFrame{
				Offset: 2,
				Data:   []byte("obar"),
			}
			err := str.HandleStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.HandleStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b).To(Equal([]byte("foobar")))
		})

		It("calls onData", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false)
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
			frame := wire.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			str.HandleStreamFrame(&frame)
			b := make([]byte, 4)
			_, err := strWithTimeout.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(onDataCalled).To(BeTrue())
		})

		Context("deadlines", func() {
			It("the deadline error has the right net.Error properties", func() {
				Expect(errDeadline.Temporary()).To(BeTrue())
				Expect(errDeadline.Timeout()).To(BeTrue())
				Expect(errDeadline).To(MatchError("deadline exceeded"))
			})

			It("returns an error when Read is called after the deadline", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false).AnyTimes()
				f := &wire.StreamFrame{Data: []byte("foobar")}
				err := str.HandleStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
				str.SetReadDeadline(time.Now().Add(-time.Second))
				b := make([]byte, 6)
				n, err := strWithTimeout.Read(b)
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
			})

			It("unblocks after the deadline", func() {
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetReadDeadline(deadline)
				b := make([]byte, 6)
				n, err := strWithTimeout.Read(b)
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(10*time.Millisecond)))
			})

			It("doesn't unblock if the deadline is changed before the first one expires", func() {
				deadline1 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(100 * time.Millisecond))
				str.SetReadDeadline(deadline1)
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(20 * time.Millisecond))
					str.SetReadDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline1))
				}()
				runtime.Gosched()
				b := make([]byte, 10)
				n, err := strWithTimeout.Read(b)
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(20*time.Millisecond)))
			})

			It("unblocks earlier, when a new deadline is set", func() {
				deadline1 := time.Now().Add(scaleDuration(200 * time.Millisecond))
				deadline2 := time.Now().Add(scaleDuration(50 * time.Millisecond))
				go func() {
					defer GinkgoRecover()
					time.Sleep(scaleDuration(10 * time.Millisecond))
					str.SetReadDeadline(deadline2)
					// make sure that this was actually execute before the deadline expires
					Expect(time.Now()).To(BeTemporally("<", deadline2))
				}()
				str.SetReadDeadline(deadline1)
				runtime.Gosched()
				b := make([]byte, 10)
				_, err := strWithTimeout.Read(b)
				Expect(err).To(MatchError(errDeadline))
				Expect(time.Now()).To(BeTemporally("~", deadline2, scaleDuration(25*time.Millisecond)))
			})

			It("sets a read deadline, when SetDeadline is called", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), false).AnyTimes()
				f := &wire.StreamFrame{Data: []byte("foobar")}
				err := str.HandleStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
				str.SetDeadline(time.Now().Add(-time.Second))
				b := make([]byte, 6)
				n, err := strWithTimeout.Read(b)
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
			})
		})

		Context("closing", func() {
			Context("with FIN bit", func() {
				It("returns EOFs", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
					frame := wire.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
						FinBit: true,
					}
					str.HandleStreamFrame(&frame)
					b := make([]byte, 4)
					n, err := strWithTimeout.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(4))
					Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
					n, err = strWithTimeout.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})

				It("handles out-of-order frames", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), false)
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2)).Times(2)
					frame1 := wire.StreamFrame{
						Offset: 2,
						Data:   []byte{0xBE, 0xEF},
						FinBit: true,
					}
					frame2 := wire.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD},
					}
					err := str.HandleStreamFrame(&frame1)
					Expect(err).ToNot(HaveOccurred())
					err = str.HandleStreamFrame(&frame2)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := strWithTimeout.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(4))
					Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
					n, err = strWithTimeout.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})

				It("returns EOFs with partial read", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(2), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
					frame := wire.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD},
						FinBit: true,
					}
					err := str.HandleStreamFrame(&frame)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := strWithTimeout.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(2))
					Expect(b[:n]).To(Equal([]byte{0xDE, 0xAD}))
				})

				It("handles immediate FINs", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(0), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(0))
					frame := wire.StreamFrame{
						Offset: 0,
						Data:   []byte{},
						FinBit: true,
					}
					err := str.HandleStreamFrame(&frame)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := strWithTimeout.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})
			})

			Context("when CloseRemote is called", func() {
				It("closes", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(0), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(0))
					str.CloseRemote(0)
					b := make([]byte, 8)
					n, err := strWithTimeout.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})

				It("doesn't cancel the context", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(0), true)
					str.CloseRemote(0)
					Expect(str.Context().Done()).ToNot(BeClosed())
				})
			})
		})

		Context("cancelling the stream", func() {
			testErr := errors.New("test error")

			It("immediately returns all reads", func() {
				done := make(chan struct{})
				b := make([]byte, 4)
				go func() {
					defer GinkgoRecover()
					n, err := strWithTimeout.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(testErr))
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				str.CloseForShutdown(testErr)
				Eventually(done).Should(BeClosed())
			})

			It("errors for all following reads", func() {
				str.CloseForShutdown(testErr)
				b := make([]byte, 1)
				n, err := strWithTimeout.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("cancels the context", func() {
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.CloseForShutdown(testErr)
				Expect(str.Context().Done()).To(BeClosed())
			})
		})
	})

	Context("writing", func() {
		It("writes and gets all data at once", func() {
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
			Consistently(done).ShouldNot(BeClosed())
			Expect(onDataCalled).To(BeTrue())
			f := str.PopStreamFrame(1000)
			Expect(f.Data).To(Equal([]byte("foobar")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(BeZero())
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("writes and gets data in two turns", func() {
			frameHeaderLen := protocol.ByteCount(4)
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
			mockFC.EXPECT().AddBytesSent(gomock.Any() /* protocol.ByteCount(3)*/).Times(2)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
			Consistently(done).ShouldNot(BeClosed())
			f := str.PopStreamFrame(3 + frameHeaderLen)
			Expect(f.Data).To(Equal([]byte("foo")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(BeZero())
			Expect(f.DataLenPresent).To(BeTrue())
			f = str.PopStreamFrame(100)
			Expect(f.Data).To(Equal([]byte("bar")))
			Expect(f.FinBit).To(BeFalse())
			Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
			Expect(f.DataLenPresent).To(BeTrue())
			Expect(str.PopStreamFrame(1000)).To(BeNil())
			Eventually(done).Should(BeClosed())
		})

		It("PopStreamFrame returns nil if no data is available", func() {
			Expect(str.PopStreamFrame(1000)).To(BeNil())
		})

		It("copies the slice while writing", func() {
			frameHeaderSize := protocol.ByteCount(4)
			mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(1))
			mockFC.EXPECT().AddBytesSent(protocol.ByteCount(2))
			s := []byte("foo")
			go func() {
				defer GinkgoRecover()
				n, err := strWithTimeout.Write(s)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
			}()
			var frame *wire.StreamFrame
			Eventually(func() *wire.StreamFrame { frame = str.PopStreamFrame(frameHeaderSize + 1); return frame }).ShouldNot(BeNil())
			Expect(frame.Data).To(Equal([]byte("f")))
			s[1] = 'e'
			f := str.PopStreamFrame(100)
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
			Expect(str.Context().Done()).ToNot(BeClosed())
			str.Close()
			Expect(str.Context().Done()).To(BeClosed())
		})

		Context("deadlines", func() {
			It("returns an error when Write is called after the deadline", func() {
				str.SetWriteDeadline(time.Now().Add(-time.Second))
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
			})

			It("unblocks after the deadline", func() {
				deadline := time.Now().Add(scaleDuration(50 * time.Millisecond))
				str.SetWriteDeadline(deadline)
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
				Expect(time.Now()).To(BeTemporally("~", deadline, scaleDuration(20*time.Millisecond)))
			})

			It("returns the number of bytes written, when the deadline expires", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(10000)).AnyTimes()
				mockFC.EXPECT().AddBytesSent(gomock.Any())
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
					defer GinkgoRecover()
					frame = str.PopStreamFrame(50)
					return frame
				}).ShouldNot(BeNil())
				Eventually(writeReturned, scaleDuration(80*time.Millisecond)).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.DataLen()))
			})

			It("doesn't unblock if the deadline is changed before the first one expires", func() {
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

			It("sets a read deadline, when SetDeadline is called", func() {
				str.SetDeadline(time.Now().Add(-time.Second))
				n, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError(errDeadline))
				Expect(n).To(BeZero())
			})
		})

		Context("closing", func() {
			It("doesn't allow writes after it has been closed", func() {
				str.Close()
				_, err := strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError("write on closed stream 1337"))
			})

			It("allows FIN", func() {
				str.Close()
				f := str.PopStreamFrame(1000)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(BeEmpty())
				Expect(f.FinBit).To(BeTrue())
			})

			It("doesn't allow FIN when there's still data", func() {
				frameHeaderLen := protocol.ByteCount(4)
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999)).Times(2)
				mockFC.EXPECT().AddBytesSent(gomock.Any()).Times(2)
				str.dataForWriting = []byte("foobar")
				str.Close()
				f := str.PopStreamFrame(3 + frameHeaderLen)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(Equal([]byte("foo")))
				Expect(f.FinBit).To(BeFalse())
				f = str.PopStreamFrame(100)
				Expect(f.Data).To(Equal([]byte("bar")))
				Expect(f.FinBit).To(BeTrue())
			})

			It("doesn't allow FIN after an error", func() {
				str.CloseForShutdown(errors.New("test"))
				f := str.PopStreamFrame(1000)
				Expect(f).To(BeNil())
			})

			It("doesn't allow FIN twice", func() {
				str.Close()
				f := str.PopStreamFrame(1000)
				Expect(f).ToNot(BeNil())
				Expect(f.Data).To(BeEmpty())
				Expect(f.FinBit).To(BeTrue())
				Expect(str.PopStreamFrame(1000)).To(BeNil())
			})
		})

		Context("closing abruptly", func() {
			testErr := errors.New("test")

			It("returns errors when the stream is cancelled", func() {
				str.CloseForShutdown(testErr)
				n, err := strWithTimeout.Write([]byte("foo"))
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("doesn't get data for writing if an error occurred", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.ByteCount(9999))
				mockFC.EXPECT().AddBytesSent(gomock.Any())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Write(bytes.Repeat([]byte{0}, 500))
					Expect(err).To(MatchError(testErr))
					close(done)
				}()
				Eventually(func() *wire.StreamFrame { return str.PopStreamFrame(50) }).ShouldNot(BeNil()) // get a STREAM frame containing some data, but not all
				str.CloseForShutdown(testErr)
				Expect(str.PopStreamFrame(1000)).To(BeNil())
				Eventually(done).Should(BeClosed())
			})
		})
	})

	Context("stream cancelations", func() {
		Context("canceling writing", func() {
			It("queues a RST_STREAM frame", func() {
				str.writeOffset = 1234
				err := str.CancelWrite(9876)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(Equal([]wire.Frame{
					&wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 1234,
						ErrorCode:  9876,
					},
				}))
			})

			It("unblocks Write", func() {
				mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount)
				mockFC.EXPECT().AddBytesSent(gomock.Any())
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
					defer GinkgoRecover()
					frame = str.PopStreamFrame(50)
					return frame
				}).ShouldNot(BeNil())
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				Eventually(writeReturned).Should(BeClosed())
				Expect(n).To(BeEquivalentTo(frame.DataLen()))
			})

			It("cancels the context", func() {
				Expect(str.Context().Done()).ToNot(BeClosed())
				str.CancelWrite(1234)
				Expect(str.Context().Done()).To(BeClosed())
			})

			It("doesn't allow further calls to Write", func() {
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				_, err = strWithTimeout.Write([]byte("foobar"))
				Expect(err).To(MatchError("Write on stream 1337 canceled with error code 1234"))
			})

			It("only cancels once", func() {
				err := str.CancelWrite(1234)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(HaveLen(1))
				err = str.CancelWrite(4321)
				Expect(err).ToNot(HaveOccurred())
				Expect(queuedControlFrames).To(HaveLen(1))
			})

			It("doesn't cancel when the stream was already closed", func() {
				err := str.Close()
				Expect(err).ToNot(HaveOccurred())
				err = str.CancelWrite(123)
				Expect(err).To(MatchError("CancelWrite for closed stream 1337"))
			})
		})

		Context("canceling read", func() {
			It("unblocks Read", func() {
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Read([]byte{0})
					Expect(err).To(MatchError("Read on stream 1337 canceled with error code 1234"))
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				err := str.CancelRead(1234)
				Expect(err).ToNot(HaveOccurred())
				Eventually(done).Should(BeClosed())
			})

			It("doesn't allow further calls to Read", func() {
				err := str.CancelRead(1234)
				Expect(err).ToNot(HaveOccurred())
				_, err = strWithTimeout.Read([]byte{0})
				Expect(err).To(MatchError("Read on stream 1337 canceled with error code 1234"))
			})

			It("does nothing when CancelRead is called twice", func() {
				err := str.CancelRead(1234)
				Expect(err).ToNot(HaveOccurred())
				err = str.CancelRead(2345)
				Expect(err).ToNot(HaveOccurred())
				_, err = strWithTimeout.Read([]byte{0})
				Expect(err).To(MatchError("Read on stream 1337 canceled with error code 1234"))
			})

			Context("for gQUIC", func() {
				It("sends a RST_STREAM with error code 0, after the stream is closed", func() {
					str.version = versionGQUICFrames
					mockFC.EXPECT().SendWindowSize().Return(protocol.MaxByteCount).AnyTimes()
					mockFC.EXPECT().AddBytesSent(protocol.ByteCount(6))
					err := str.CancelRead(1234)
					Expect(err).ToNot(HaveOccurred())
					Expect(queuedControlFrames).To(BeEmpty()) // no RST_STREAM frame queued yet
					writeReturned := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, err := strWithTimeout.Write([]byte("foobar"))
						Expect(err).ToNot(HaveOccurred())
						close(writeReturned)
					}()
					Eventually(func() *wire.StreamFrame { return str.PopStreamFrame(1000) }).ShouldNot(BeNil())
					Eventually(writeReturned).Should(BeClosed())
					Expect(queuedControlFrames).To(BeEmpty()) // no RST_STREAM frame queued yet
					err = str.Close()
					Expect(err).ToNot(HaveOccurred())
					Expect(queuedControlFrames).To(Equal([]wire.Frame{
						&wire.RstStreamFrame{
							StreamID:   streamID,
							ByteOffset: 6,
							ErrorCode:  0,
						},
					}))
				})

				It("doesn't send a RST_STREAM frame, if the FIN was already read", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(6))
					err := str.HandleStreamFrame(&wire.StreamFrame{
						StreamID: streamID,
						Data:     []byte("foobar"),
						FinBit:   true,
					})
					Expect(err).ToNot(HaveOccurred())
					_, err = strWithTimeout.Read(make([]byte, 100))
					Expect(err).To(MatchError(io.EOF))
					err = str.CancelRead(1234)
					Expect(err).ToNot(HaveOccurred())
					Expect(queuedControlFrames).To(BeEmpty()) // no RST_STREAM frame queued yet
				})
			})
		})

		Context("receiving RST_STREAM frames", func() {
			rst := &wire.RstStreamFrame{
				StreamID:   streamID,
				ByteOffset: 42,
				ErrorCode:  1234,
			}

			It("unblocks Read", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := strWithTimeout.Read([]byte{0})
					Expect(err).To(MatchError("Stream 1337 was reset with error code 1234"))
					Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
					Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
					Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(1234)))
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())
				str.HandleRstStreamFrame(rst)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't allow further calls to Read", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true)
				err := str.HandleRstStreamFrame(rst)
				Expect(err).ToNot(HaveOccurred())
				_, err = strWithTimeout.Read([]byte{0})
				Expect(err).To(MatchError("Stream 1337 was reset with error code 1234"))
				Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
				Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
				Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(1234)))
			})

			It("errors when receiving a RST_STREAM with an inconsistent offset", func() {
				testErr := errors.New("already received a different final offset before")
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true).Return(testErr)
				err := str.HandleRstStreamFrame(rst)
				Expect(err).To(MatchError(testErr))
			})

			It("ignores duplicate RST_STREAM frames", func() {
				mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true).Times(2)
				err := str.HandleRstStreamFrame(rst)
				Expect(err).ToNot(HaveOccurred())
				err = str.HandleRstStreamFrame(rst)
				Expect(err).ToNot(HaveOccurred())
			})

			It("doesn't do anyting when it was closed for shutdown", func() {
				str.CloseForShutdown(nil)
				err := str.HandleRstStreamFrame(rst)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("for gQUIC", func() {
				BeforeEach(func() {
					str.version = versionGQUICFrames
				})

				It("unblocks Read when receiving a RST_STREAM frame with non-zero error code", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(42), true)
					readReturned := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, err := strWithTimeout.Read([]byte{0})
						Expect(err).To(MatchError("Stream 1337 was reset with error code 1234"))
						Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
						Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
						Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(1234)))
						close(readReturned)
					}()
					Consistently(readReturned).ShouldNot(BeClosed())
					err := str.HandleRstStreamFrame(rst)
					Expect(err).ToNot(HaveOccurred())
					Eventually(readReturned).Should(BeClosed())
				})

				It("unblocks Write when receiving a RST_STREAM frame with non-zero error code", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true)
					str.writeOffset = 1000
					f := &wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 6,
						ErrorCode:  123,
					}
					writeReturned := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, err := strWithTimeout.Write([]byte("foobar"))
						Expect(err).To(MatchError("Stream 1337 was reset with error code 123"))
						Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
						Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
						Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(123)))
						close(writeReturned)
					}()
					Consistently(writeReturned).ShouldNot(BeClosed())
					err := str.HandleRstStreamFrame(f)
					Expect(err).ToNot(HaveOccurred())
					Expect(queuedControlFrames).To(Equal([]wire.Frame{
						&wire.RstStreamFrame{
							StreamID:   streamID,
							ByteOffset: 1000,
							ErrorCode:  errorCodeStoppingGQUIC,
						},
					}))
					Eventually(writeReturned).Should(BeClosed())
				})

				It("sends a RST_STREAM and continues reading until the end when receiving a RST_STREAM frame with error code 0", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true).Times(2)
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
					mockFC.EXPECT().AddBytesRead(protocol.ByteCount(2))
					readReturned := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						n, err := strWithTimeout.Read(make([]byte, 4))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(4))
						n, err = strWithTimeout.Read(make([]byte, 4))
						Expect(err).To(MatchError(io.EOF))
						Expect(n).To(Equal(2))
						close(readReturned)
					}()
					Consistently(readReturned).ShouldNot(BeClosed())
					err := str.HandleStreamFrame(&wire.StreamFrame{
						StreamID: streamID,
						Data:     []byte("foobar"),
						FinBit:   true,
					})
					Expect(err).ToNot(HaveOccurred())
					err = str.HandleRstStreamFrame(&wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 6,
						ErrorCode:  0,
					})
					Expect(err).ToNot(HaveOccurred())
					Eventually(readReturned).Should(BeClosed())
				})

				It("unblocks Write when receiving a RST_STREAM frame with error code 0", func() {
					mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(6), true)
					str.writeOffset = 1000
					f := &wire.RstStreamFrame{
						StreamID:   streamID,
						ByteOffset: 6,
						ErrorCode:  0,
					}
					writeReturned := make(chan struct{})
					go func() {
						defer GinkgoRecover()
						_, err := strWithTimeout.Write([]byte("foobar"))
						Expect(err).To(MatchError("Stream 1337 was reset with error code 0"))
						Expect(err).To(BeAssignableToTypeOf(streamCanceledError{}))
						Expect(err.(streamCanceledError).Canceled()).To(BeTrue())
						Expect(err.(streamCanceledError).ErrorCode()).To(Equal(protocol.ApplicationErrorCode(0)))
						close(writeReturned)
					}()
					Consistently(writeReturned).ShouldNot(BeClosed())
					err := str.HandleRstStreamFrame(f)
					Expect(err).ToNot(HaveOccurred())
					Expect(queuedControlFrames).To(Equal([]wire.Frame{
						&wire.RstStreamFrame{
							StreamID:   streamID,
							ByteOffset: 1000,
							ErrorCode:  errorCodeStoppingGQUIC,
						},
					}))
					Eventually(writeReturned).Should(BeClosed())
				})
			})
		})
	})

	Context("saying if it is finished", func() {
		testErr := errors.New("testErr")

		finishReading := func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(0), true)
			err := str.HandleStreamFrame(&wire.StreamFrame{FinBit: true})
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 100)
			_, err = strWithTimeout.Read(b)
			Expect(err).To(MatchError(io.EOF))
		}

		It("is finished after it is closed for shutdown", func() {
			str.CloseForShutdown(testErr)
			Expect(str.Finished()).To(BeTrue())
		})

		It("is not finished if it is only closed for writing", func() {
			str.Close()
			f := str.PopStreamFrame(1000)
			Expect(f.FinBit).To(BeTrue())
			Expect(str.Finished()).To(BeFalse())
		})

		It("cancels the context after it is closed", func() {
			Expect(str.Context().Done()).ToNot(BeClosed())
			str.Close()
			Expect(str.Context().Done()).To(BeClosed())
		})

		It("is not finished if it is only closed for reading", func() {
			mockFC.EXPECT().AddBytesRead(protocol.ByteCount(0))
			finishReading()
			Expect(str.Finished()).To(BeFalse())
		})

		It("is finished after finishing writing and receiving a RST", func() {
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(13), true)
			str.Close()
			f := str.PopStreamFrame(1000)
			Expect(f.FinBit).To(BeTrue())
			str.HandleRstStreamFrame(&wire.RstStreamFrame{
				StreamID:   streamID,
				ByteOffset: 13,
			})
			Expect(str.Finished()).To(BeTrue())
		})
	})

	Context("flow control", func() {
		It("errors when a STREAM frame causes a flow control violation", func() {
			testErr := errors.New("flow control violation")
			mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false).Return(testErr)
			frame := wire.StreamFrame{
				Offset: 2,
				Data:   []byte("foobar"),
			}
			err := str.HandleStreamFrame(&frame)
			Expect(err).To(MatchError(testErr))
		})

		It("says when it's flow control blocked", func() {
			mockFC.EXPECT().IsBlocked().Return(false, protocol.ByteCount(0))
			blocked, _ := str.IsFlowControlBlocked()
			Expect(blocked).To(BeFalse())
			mockFC.EXPECT().IsBlocked().Return(true, protocol.ByteCount(0x1337))
			blocked, offset := str.IsFlowControlBlocked()
			Expect(blocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(0x1337)))
		})

		It("updates the flow control window", func() {
			mockFC.EXPECT().UpdateSendWindow(protocol.ByteCount(0x42))
			str.HandleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
				StreamID:   streamID,
				ByteOffset: 0x42,
			})
		})

		It("gets a window update", func() {
			mockFC.EXPECT().GetWindowUpdate().Return(protocol.ByteCount(0x100))
			Expect(str.GetWindowUpdate()).To(Equal(protocol.ByteCount(0x100)))
		})
	})
})
