package quic

import (
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream", func() {
	const streamID protocol.StreamID = 1337

	var (
		str          *stream
		onDataCalled bool

		resetCalled          bool
		resetCalledForStream protocol.StreamID
		resetCalledAtOffset  protocol.ByteCount

		mockFcm *mocks.MockFlowControlManager
	)

	onData := func() {
		onDataCalled = true
	}

	onReset := func(id protocol.StreamID, offset protocol.ByteCount) {
		resetCalled = true
		resetCalledForStream = id
		resetCalledAtOffset = offset
	}

	BeforeEach(func() {
		onDataCalled = false
		resetCalled = false
		mockFcm = mocks.NewMockFlowControlManager(mockCtrl)
		str = newStream(streamID, onData, onReset, mockFcm)
	})

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	Context("reading", func() {
		It("reads a single StreamFrame", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(4))
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("reads a single StreamFrame in multiple goes", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2))
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 2)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xDE, 0xAD}))
			n, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b).To(Equal([]byte{0xBE, 0xEF}))
		})

		It("reads all data available", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2)).Times(2)
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}))
		})

		It("assembles multiple StreamFrames", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2)).Times(2)
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("waits until data is available", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2))
			go func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD},
				}
				time.Sleep(time.Millisecond)
				err := str.AddStreamFrame(&frame)
				Expect(err).ToNot(HaveOccurred())
			}()
			b := make([]byte, 2)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
		})

		It("handles StreamFrames in wrong order", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2)).Times(2)
			frame1 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			frame2 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("ignores duplicate StreamFrames", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2)).Times(2)
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0x13, 0x37},
			}
			frame3 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte{0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame3)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
		})

		It("doesn't rejects a StreamFrames with an overlapping data range", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(6))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(4))
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte("foob"),
			}
			frame2 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte("obar"),
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b).To(Equal([]byte("foobar")))
		})

		It("calls onData", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(4))
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			str.AddStreamFrame(&frame)
			b := make([]byte, 4)
			_, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(onDataCalled).To(BeTrue())
		})

		Context("closing", func() {
			Context("with FIN bit", func() {
				It("returns EOFs", func() {
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
					mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(4))
					frame := frames.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
						FinBit: true,
					}
					str.AddStreamFrame(&frame)
					b := make([]byte, 4)
					n, err := str.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(4))
					Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
					n, err = str.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})

				It("handles out-of-order frames", func() {
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
					mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2)).Times(2)
					frame1 := frames.StreamFrame{
						Offset: 2,
						Data:   []byte{0xBE, 0xEF},
						FinBit: true,
					}
					frame2 := frames.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD},
					}
					err := str.AddStreamFrame(&frame1)
					Expect(err).ToNot(HaveOccurred())
					err = str.AddStreamFrame(&frame2)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := str.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(4))
					Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
					n, err = str.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})

				It("returns EOFs with partial read", func() {
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(2))
					mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(2))
					frame := frames.StreamFrame{
						Offset: 0,
						Data:   []byte{0xDE, 0xAD},
						FinBit: true,
					}
					err := str.AddStreamFrame(&frame)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := str.Read(b)
					Expect(err).To(MatchError(io.EOF))
					Expect(n).To(Equal(2))
					Expect(b[:n]).To(Equal([]byte{0xDE, 0xAD}))
				})

				It("handles immediate FINs", func() {
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(0))
					mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(0))
					frame := frames.StreamFrame{
						Offset: 0,
						Data:   []byte{},
						FinBit: true,
					}
					err := str.AddStreamFrame(&frame)
					Expect(err).ToNot(HaveOccurred())
					b := make([]byte, 4)
					n, err := str.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})
			})

			Context("when CloseRemote is called", func() {
				It("closes", func() {
					mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(0))
					mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(0))
					str.CloseRemote(0)
					b := make([]byte, 8)
					n, err := str.Read(b)
					Expect(n).To(BeZero())
					Expect(err).To(MatchError(io.EOF))
				})
			})
		})

		Context("cancelling the stream", func() {
			testErr := errors.New("test error")

			It("immediately returns all reads", func() {
				var readReturned bool
				var n int
				var err error
				b := make([]byte, 4)
				go func() {
					n, err = str.Read(b)
					readReturned = true
				}()
				Consistently(func() bool { return readReturned }).Should(BeFalse())
				str.Cancel(testErr)
				Eventually(func() bool { return readReturned }).Should(BeTrue())
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("errors for all following reads", func() {
				str.Cancel(testErr)
				b := make([]byte, 1)
				n, err := str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})
		})
	})

	Context("resetting", func() {
		testErr := errors.New("testErr")

		Context("reset by the peer", func() {
			It("continues reading after receiving a remote error", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				str.AddStreamFrame(&frame)
				str.RegisterRemoteError(testErr)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
			})

			It("reads a delayed StreamFrame that arrives after receiving a remote error", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				str.RegisterRemoteError(testErr)
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				err := str.AddStreamFrame(&frame)
				Expect(err).ToNot(HaveOccurred())
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
			})

			It("returns the error if reading past the offset of the frame received", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				str.AddStreamFrame(&frame)
				str.RegisterRemoteError(testErr)
				b := make([]byte, 10)
				n, err := str.Read(b)
				Expect(b[0:4]).To(Equal(frame.Data))
				Expect(err).To(MatchError(testErr))
				Expect(n).To(Equal(4))
			})

			It("returns an EOF when reading past the offset, if the stream received a finbit", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
					FinBit: true,
				}
				str.AddStreamFrame(&frame)
				str.RegisterRemoteError(testErr)
				b := make([]byte, 10)
				n, err := str.Read(b)
				Expect(b[:4]).To(Equal(frame.Data))
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(Equal(4))
			})

			It("continues reading in small chunks after receiving a remote error", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
					FinBit: true,
				}
				str.AddStreamFrame(&frame)
				str.RegisterRemoteError(testErr)
				b := make([]byte, 3)
				_, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(Equal([]byte{0xde, 0xad, 0xbe}))
				b = make([]byte, 3)
				n, err := str.Read(b)
				Expect(err).To(MatchError(io.EOF))
				Expect(b[:1]).To(Equal([]byte{0xef}))
				Expect(n).To(Equal(1))
			})

			It("doesn't inform the flow controller about bytes read after receiving the remote error", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(4))
				// No AddBytesRead()
				frame := frames.StreamFrame{
					Offset:   0,
					StreamID: 5,
					Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				str.AddStreamFrame(&frame)
				str.RegisterRemoteError(testErr)
				b := make([]byte, 3)
				_, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
			})

			It("stops writing after receiving a remote error", func() {
				var writeReturned bool
				var n int
				var err error

				go func() {
					n, err = str.Write([]byte("foobar"))
					writeReturned = true
				}()
				str.RegisterRemoteError(testErr)
				Eventually(func() bool { return writeReturned }).Should(BeTrue())
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("calls onReset when receiving a remote error", func() {
				var writeReturned bool
				str.writeOffset = 0x1000
				go func() {
					str.Write([]byte("foobar"))
					writeReturned = true
				}()
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeTrue())
				Expect(resetCalledForStream).To(Equal(protocol.StreamID(1337)))
				Expect(resetCalledAtOffset).To(Equal(protocol.ByteCount(0x1000)))
				Eventually(func() bool { return writeReturned }).Should(BeTrue())
			})

			It("doesn't call onReset if it already sent a FIN", func() {
				str.Close()
				str.sentFin()
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeFalse())
			})

			It("doesn't call onReset if the stream was reset locally before", func() {
				str.Reset(testErr)
				Expect(resetCalled).To(BeTrue())
				resetCalled = false
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeFalse())
			})

			It("doesn't call onReset twice, when it gets two remote errors", func() {
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeTrue())
				resetCalled = false
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeFalse())
			})
		})

		Context("reset locally", func() {
			It("stops writing", func() {
				var writeReturned bool
				var n int
				var err error

				go func() {
					n, err = str.Write([]byte("foobar"))
					writeReturned = true
				}()
				Consistently(func() bool { return writeReturned }).Should(BeFalse())
				str.Reset(testErr)
				Expect(str.getDataForWriting(6)).To(BeNil())
				Eventually(func() bool { return writeReturned }).Should(BeTrue())
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("doesn't allow further writes", func() {
				str.Reset(testErr)
				n, err := str.Write([]byte("foobar"))
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
				Expect(str.getDataForWriting(6)).To(BeNil())
			})

			It("stops reading", func() {
				var readReturned bool
				var n int
				var err error

				go func() {
					b := make([]byte, 4)
					n, err = str.Read(b)
					readReturned = true
				}()
				Consistently(func() bool { return readReturned }).Should(BeFalse())
				str.Reset(testErr)
				Eventually(func() bool { return readReturned }).Should(BeTrue())
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("doesn't allow further reads", func() {
				mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(6))
				str.AddStreamFrame(&frames.StreamFrame{
					Data: []byte("foobar"),
				})
				str.Reset(testErr)
				b := make([]byte, 6)
				n, err := str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("calls onReset", func() {
				str.writeOffset = 0x1000
				str.Reset(testErr)
				Expect(resetCalled).To(BeTrue())
				Expect(resetCalledForStream).To(Equal(protocol.StreamID(1337)))
				Expect(resetCalledAtOffset).To(Equal(protocol.ByteCount(0x1000)))
			})

			It("doesn't call onReset if it already sent a FIN", func() {
				str.Close()
				str.sentFin()
				str.Reset(testErr)
				Expect(resetCalled).To(BeFalse())
			})

			It("doesn't call onReset if the stream was reset remotely before", func() {
				str.RegisterRemoteError(testErr)
				Expect(resetCalled).To(BeTrue())
				resetCalled = false
				str.Reset(testErr)
				Expect(resetCalled).To(BeFalse())
			})

			It("doesn't call onReset twice", func() {
				str.Reset(testErr)
				Expect(resetCalled).To(BeTrue())
				resetCalled = false
				str.Reset(testErr)
				Expect(resetCalled).To(BeFalse())
			})
		})
	})

	Context("writing", func() {
		It("writes and gets all data at once", func(done Done) {
			var writeReturned bool
			go func() {
				n, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				writeReturned = true
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
			Consistently(func() bool { return writeReturned }).Should(BeFalse())
			Expect(onDataCalled).To(BeTrue())
			Expect(str.lenOfDataForWriting()).To(Equal(protocol.ByteCount(6)))
			data := str.getDataForWriting(1000)
			Expect(data).To(Equal([]byte("foobar")))
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
			Eventually(func() bool { return writeReturned }).Should(BeTrue())
			close(done)
		})

		It("writes and gets data in two turns", func(done Done) {
			var writeReturned bool
			go func() {
				n, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				writeReturned = true
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
			Consistently(func() bool { return writeReturned }).Should(BeFalse())
			Expect(str.lenOfDataForWriting()).To(Equal(protocol.ByteCount(6)))
			data := str.getDataForWriting(3)
			Expect(data).To(Equal([]byte("foo")))
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(3)))
			Expect(str.dataForWriting).ToNot(BeNil())
			Expect(str.lenOfDataForWriting()).To(Equal(protocol.ByteCount(3)))
			data = str.getDataForWriting(3)
			Expect(data).To(Equal([]byte("bar")))
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
			Expect(str.lenOfDataForWriting()).To(Equal(protocol.ByteCount(0)))
			Eventually(func() bool { return writeReturned }).Should(BeTrue())
			close(done)
		})

		It("getDataForWriting returns nil if no data is available", func() {
			Expect(str.getDataForWriting(1000)).To(BeNil())
		})

		It("copies the slice while writing", func() {
			s := []byte("foo")
			go func() {
				n, err := str.Write(s)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
			}()
			Eventually(func() protocol.ByteCount { return str.lenOfDataForWriting() }).ShouldNot(BeZero())
			s[0] = 'v'
			Expect(str.getDataForWriting(3)).To(Equal([]byte("foo")))
		})

		It("returns when given a nil input", func() {
			n, err := str.Write(nil)
			Expect(n).To(BeZero())
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns when given an empty slice", func() {
			n, err := str.Write([]byte(""))
			Expect(n).To(BeZero())
			Expect(err).ToNot(HaveOccurred())
		})

		Context("closing", func() {
			It("sets finishedWriting when calling Close", func() {
				str.Close()
				Expect(str.finishedWriting.Get()).To(BeTrue())
			})

			It("allows FIN", func() {
				str.Close()
				Expect(str.shouldSendFin()).To(BeTrue())
			})

			It("does not allow FIN when there's still data", func() {
				str.dataForWriting = []byte("foobar")
				str.Close()
				Expect(str.shouldSendFin()).To(BeFalse())
			})

			It("does not allow FIN when the stream is not closed", func() {
				Expect(str.shouldSendFin()).To(BeFalse())
			})

			It("does not allow FIN after an error", func() {
				str.Cancel(errors.New("test"))
				Expect(str.shouldSendFin()).To(BeFalse())
			})

			It("does not allow FIN twice", func() {
				str.Close()
				Expect(str.shouldSendFin()).To(BeTrue())
				str.sentFin()
				Expect(str.shouldSendFin()).To(BeFalse())
			})
		})

		Context("cancelling", func() {
			testErr := errors.New("test")

			It("returns errors when the stream is cancelled", func() {
				str.Cancel(testErr)
				n, err := str.Write([]byte("foo"))
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})

			It("doesn't get data for writing if an error occurred", func() {
				go func() {
					_, err := str.Write([]byte("foobar"))
					Expect(err).To(MatchError(testErr))
				}()
				Eventually(func() []byte { return str.dataForWriting }).ShouldNot(BeNil())
				Expect(str.lenOfDataForWriting()).ToNot(BeZero())
				str.Cancel(testErr)
				data := str.getDataForWriting(6)
				Expect(data).To(BeNil())
				Expect(str.lenOfDataForWriting()).To(BeZero())
			})
		})
	})

	It("errors when a StreamFrames causes a flow control violation", func() {
		testErr := errors.New("flow control violation")
		mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(8)).Return(testErr)
		frame := frames.StreamFrame{
			Offset: 2,
			Data:   []byte("foobar"),
		}
		err := str.AddStreamFrame(&frame)
		Expect(err).To(MatchError(testErr))
	})

	Context("closing", func() {
		testErr := errors.New("testErr")

		finishReading := func() {
			err := str.AddStreamFrame(&frames.StreamFrame{FinBit: true})
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 100)
			_, err = str.Read(b)
			Expect(err).To(MatchError(io.EOF))
		}

		It("is finished after it is canceled", func() {
			str.Cancel(testErr)
			Expect(str.finished()).To(BeTrue())
		})

		It("is not finished if it is only closed for writing", func() {
			str.Close()
			str.sentFin()
			Expect(str.finished()).To(BeFalse())
		})

		It("is not finished if it is only closed for reading", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(0))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(0))
			finishReading()
			Expect(str.finished()).To(BeFalse())
		})

		It("is finished after receiving a RST and sending one", func() {
			// this directly sends a rst
			str.RegisterRemoteError(testErr)
			Expect(str.rstSent.Get()).To(BeTrue())
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after being locally reset and receiving a RST in response", func() {
			str.Reset(testErr)
			Expect(str.finished()).To(BeFalse())
			str.RegisterRemoteError(testErr)
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after finishing writing and receiving a RST", func() {
			str.Close()
			str.sentFin()
			str.RegisterRemoteError(testErr)
			Expect(str.finished()).To(BeTrue())
		})

		It("is finished after finishing reading and being locally reset", func() {
			mockFcm.EXPECT().UpdateHighestReceived(streamID, protocol.ByteCount(0))
			mockFcm.EXPECT().AddBytesRead(streamID, protocol.ByteCount(0))
			finishReading()
			Expect(str.finished()).To(BeFalse())
			str.Reset(testErr)
			Expect(str.finished()).To(BeTrue())
		})
	})
})
