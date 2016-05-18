package quic

import (
	"bytes"
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStreamHandler struct {
	frames []frames.Frame

	receivedBlockedCalled    bool
	receivedBlockedForStream protocol.StreamID

	receiveFlowControlWindowCalled          bool
	receiveFlowControlWindowCalledForStream protocol.StreamID
}

func (m *mockStreamHandler) queueStreamFrame(f *frames.StreamFrame) error {
	m.frames = append(m.frames, f)
	return nil
}

func (m *mockStreamHandler) streamBlocked(streamID protocol.StreamID) {
	m.receivedBlockedCalled = true
	m.receivedBlockedForStream = streamID
}

func (m *mockStreamHandler) updateReceiveFlowControlWindow(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	m.receiveFlowControlWindowCalled = true
	m.receiveFlowControlWindowCalledForStream = streamID
	return nil
}

var _ = Describe("Stream", func() {
	var (
		str     *stream
		handler *mockStreamHandler
	)

	BeforeEach(func() {
		handler = &mockStreamHandler{}
		cpm := handshake.NewConnectionParamatersManager()
		str, _ = newStream(handler, cpm, 1337)
	})

	It("gets stream id", func() {
		Expect(str.StreamID()).To(Equal(protocol.StreamID(1337)))
	})

	Context("reading", func() {
		It("reads a single StreamFrame", func() {
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

		It("reads single bytes", func() {
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b, err := str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xDE)))
			b, err = str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xAD)))
			b, err = str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xBE)))
			b, err = str.ReadByte()
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal(byte(0xEF)))
		})

		It("reads all data available", func() {
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

		It("handles duplicate StreamFrames", func() {
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
			}
			frame2 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte{0xDE, 0xAD},
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

		It("discards unneeded str frames", func() {
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte("ab"),
			}
			frame2 := frames.StreamFrame{
				Offset: 1,
				Data:   []byte("xy"),
			}
			frame3 := frames.StreamFrame{
				Offset: 2,
				Data:   []byte("cd"),
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
			Expect(b).To(Equal([]byte("abyd")))
		})
	})

	Context("writing", func() {
		It("writes str frames", func() {
			n, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(handler.frames).To(HaveLen(1))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("foobar"),
			}))
		})

		It("writes multiple str frames", func() {
			n, err := str.Write([]byte("foo"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			n, err = str.Write([]byte("bar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(handler.frames).To(HaveLen(2))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("foo"),
			}))
			Expect(handler.frames[1]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				Data:     []byte("bar"),
				Offset:   3,
			}))
		})

		It("closes", func() {
			err := str.Close()
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.frames).To(HaveLen(1))
			Expect(handler.frames[0]).To(Equal(&frames.StreamFrame{
				StreamID: 1337,
				FinBit:   true,
				Offset:   0,
			}))
		})

		It("returns remote errors", func() {
			testErr := errors.New("test")
			str.RegisterError(testErr)
			n, err := str.Write([]byte("foo"))
			Expect(n).To(BeZero())
			Expect(err).To(MatchError(testErr))
		})

		Context("flow control", func() {
			It("writes everything if the flow control window is big enough", func() {
				str.flowController.sendFlowControlWindow = 4
				n, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(n).To(Equal(4))
				Expect(err).ToNot(HaveOccurred())
			})

			It("waits for a flow control window update", func() {
				var b bool
				str.flowController.sendFlowControlWindow = 1
				_, err := str.Write([]byte{0x42})
				Expect(err).ToNot(HaveOccurred())

				go func() {
					time.Sleep(2 * time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(3)
				}()
				n, err := str.Write([]byte{0x13, 0x37})
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(err).ToNot(HaveOccurred())
			})

			It("splits writing of frames when given more data than the flow control windows size", func() {
				str.flowController.sendFlowControlWindow = 2
				var b bool

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(4)
				}()

				n, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(handler.frames).To(HaveLen(2))
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(4))
				Expect(err).ToNot(HaveOccurred())
			})

			It("writes after a flow control window update", func() {
				var b bool
				str.flowController.sendFlowControlWindow = 1
				_, err := str.Write([]byte{0x42})
				Expect(err).ToNot(HaveOccurred())

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(3)
				}()
				n, err := str.Write([]byte{0xDE, 0xAD})
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(err).ToNot(HaveOccurred())
			})

			It("immediately returns on remote errors", func() {
				var b bool
				str.flowController.sendFlowControlWindow = 1

				testErr := errors.New("test error")

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.RegisterError(testErr)
				}()

				_, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(b).To(BeTrue())
				Expect(err).To(MatchError(testErr))
			})
		})
	})

	Context("Blocked streams", func() {
		It("notifies the session when a stream is flow control blocked", func() {
			str.flowController.sendFlowControlWindow = 1337
			str.flowController.bytesSent = 1337
			str.maybeTriggerBlocked()
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})

		It("notifies the session as soon as a stream is reaching the end of the window", func() {
			str.flowController.sendFlowControlWindow = 4
			str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})

		It("notifies the session as soon as a stream is flow control blocked", func() {
			str.flowController.sendFlowControlWindow = 2
			go func() {
				str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
			}()
			time.Sleep(time.Millisecond)
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})
	})

	Context("flow control window updating, for receiving", func() {
		var receiveFlowControlWindow protocol.ByteCount = 1337
		var receiveWindowUpdateThreshold protocol.ByteCount = 1000
		BeforeEach(func() {
			str.flowController.receiveFlowControlWindow = receiveFlowControlWindow
			str.flowController.receiveWindowUpdateThreshold = receiveWindowUpdateThreshold
		})

		It("updates the flow control window", func() {
			len := int(receiveFlowControlWindow) - int(receiveWindowUpdateThreshold) + 1
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   bytes.Repeat([]byte{'f'}, len),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, len)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(len))
			Expect(handler.receiveFlowControlWindowCalled).To(BeTrue())
			Expect(handler.receiveFlowControlWindowCalledForStream).To(Equal(str.streamID))
		})

		It("does not update the flow control window when not enough data was received", func() {
			len := int(receiveFlowControlWindow) - int(receiveWindowUpdateThreshold) - 1
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   bytes.Repeat([]byte{'f'}, len),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, len)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(len))
			Expect(handler.receiveFlowControlWindowCalled).To(BeFalse())
		})

		It("accepts frames that completely fill the flow control window", func() {
			len := int(receiveFlowControlWindow)
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   bytes.Repeat([]byte{'f'}, len),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects too large frames that would violate the flow control window", func() {
			len := int(protocol.ReceiveStreamFlowControlWindow) + 1
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   bytes.Repeat([]byte{'f'}, len),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).To(MatchError(errFlowControlViolation))
		})
	})

	Context("closing", func() {
		Context("with fin bit", func() {
			It("returns EOFs", func() {
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

		Context("with remote errors", func() {
			testErr := errors.New("test error")

			It("returns EOF if data is read before", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
					FinBit: true,
				}
				err := str.AddStreamFrame(&frame)
				Expect(err).ToNot(HaveOccurred())
				str.RegisterError(testErr)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).To(MatchError(io.EOF))
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(io.EOF))
			})

			It("returns errors", func() {
				frame := frames.StreamFrame{
					Offset: 0,
					Data:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
				}
				err := str.AddStreamFrame(&frame)
				Expect(err).ToNot(HaveOccurred())
				str.RegisterError(testErr)
				b := make([]byte, 4)
				n, err := str.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte{0xDE, 0xAD, 0xBE, 0xEF}))
				n, err = str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(testErr))
			})
		})
	})
})
