package quic

import (
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockStreamHandler struct {
	frames []*frames.StreamFrame

	receivedBlockedCalled    bool
	receivedBlockedForStream protocol.StreamID

	receiveFlowControlWindowCalled          bool
	receiveFlowControlWindowCalledForStream protocol.StreamID
}

func (m *mockStreamHandler) streamBlocked(streamID protocol.StreamID, byteOffset protocol.ByteCount) {
	m.receivedBlockedCalled = true
	m.receivedBlockedForStream = streamID
}

func (m *mockStreamHandler) updateReceiveFlowControlWindow(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	m.receiveFlowControlWindowCalled = true
	m.receiveFlowControlWindowCalledForStream = streamID
	return nil
}

func (m *mockStreamHandler) queueStreamFrame(f *frames.StreamFrame) error {
	m.frames = append(m.frames, f)
	return nil
}

type mockFlowControlHandler struct {
	bytesReadForStream protocol.StreamID
	bytesRead          protocol.ByteCount

	highestReceivedForStream protocol.StreamID
	highestReceived          protocol.ByteCount

	triggerStreamWindowUpdate     bool
	triggerConnectionWindowUpdate bool
}

func (m *mockFlowControlHandler) NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool) {
	panic("not implemented")
}

func (m *mockFlowControlHandler) MaybeTriggerStreamWindowUpdate(streamID protocol.StreamID) (bool, protocol.ByteCount, error) {
	return m.triggerStreamWindowUpdate, 0x1337, nil
}

func (m *mockFlowControlHandler) MaybeTriggerConnectionWindowUpdate() (bool, protocol.ByteCount) {
	return m.triggerConnectionWindowUpdate, 0x1337
}

func (m *mockFlowControlHandler) AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error {
	m.bytesReadForStream = streamID
	m.bytesRead = n
	return nil
}

func (m *mockFlowControlHandler) UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	m.highestReceivedForStream = streamID
	m.highestReceived = byteOffset
	return nil
}

var _ = Describe("Stream", func() {
	var (
		str     *stream
		handler *mockStreamHandler
	)

	BeforeEach(func() {
		var streamID protocol.StreamID = 1337
		handler = &mockStreamHandler{}
		cpm := handshake.NewConnectionParamatersManager()
		flowController := flowcontrol.NewFlowController(streamID, cpm)
		flowControlManager := flowcontrol.NewFlowControlManager(cpm)
		flowControlManager.NewStream(streamID, true)
		str, _ = newStream(handler, cpm, flowController, flowControlManager, streamID)
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

		It("ignores duplicate StreamFrames", func() {
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

		It("rejects a StreamFrames with an overlapping data range", func() {
			frame1 := frames.StreamFrame{
				Offset: 0,
				Data:   []byte("ab"),
			}
			frame2 := frames.StreamFrame{
				Offset: 1,
				Data:   []byte("xy"),
			}
			err := str.AddStreamFrame(&frame1)
			Expect(err).ToNot(HaveOccurred())
			err = str.AddStreamFrame(&frame2)
			Expect(err).To(MatchError(errOverlappingStreamData))
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
				data := []byte{0xDE, 0xCA, 0xFB, 0xAD}
				updated := str.flowController.UpdateSendWindow(4)
				Expect(updated).To(BeTrue())
				n, err := str.Write(data)
				Expect(n).To(Equal(4))
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.frames).To(HaveLen(1))
				Expect(handler.frames[0].Data).To(Equal(data))
			})

			It("doesn't care about the connection flow control window if it is not contributing", func() {
				updated := str.flowController.UpdateSendWindow(4)
				Expect(updated).To(BeTrue())
				str.contributesToConnectionFlowControl = false
				updated = str.connectionFlowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())
				n, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
			})

			It("returns true when the flow control window was updated", func() {
				updated := str.flowController.UpdateSendWindow(4)
				Expect(updated).To(BeTrue())
				updated = str.UpdateSendFlowControlWindow(5)
				Expect(updated).To(BeTrue())
			})

			It("returns false when the flow control window was not updated", func() {
				updated := str.flowController.UpdateSendWindow(4)
				Expect(updated).To(BeTrue())
				updated = str.UpdateSendFlowControlWindow(3)
				Expect(updated).To(BeFalse())
			})

			It("waits for a stream flow control window update", func() {
				var b bool
				updated := str.flowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())
				_, err := str.Write([]byte{0x42})
				Expect(err).ToNot(HaveOccurred())

				go func() {
					time.Sleep(2 * time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(3)
				}()
				n, err := str.Write([]byte{0x13, 0x37})
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(3)))
				Expect(handler.frames).To(HaveLen(2))
				Expect(handler.frames[0].Offset).To(Equal(protocol.ByteCount(0)))
				Expect(handler.frames[0].Data).To(Equal([]byte{0x42}))
				Expect(handler.frames[1].Offset).To(Equal(protocol.ByteCount(1)))
				Expect(handler.frames[1].Data).To(Equal([]byte{0x13, 0x37}))
			})

			It("does not write too much data after receiving a window update", func() {
				var b bool
				updated := str.flowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())

				go func() {
					time.Sleep(2 * time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(5)
				}()
				n, err := str.Write([]byte{0x13, 0x37})
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(2)))
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.frames).To(HaveLen(2))
				Expect(handler.frames[0].Data).To(Equal([]byte{0x13}))
				Expect(handler.frames[1].Data).To(Equal([]byte{0x37}))
			})

			It("waits for a connection flow control window update", func() {
				var b bool
				updated := str.flowController.UpdateSendWindow(1000)
				Expect(updated).To(BeTrue())
				updated = str.connectionFlowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())
				str.contributesToConnectionFlowControl = true

				_, err := str.Write([]byte{0x42})
				Expect(err).ToNot(HaveOccurred())
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(1)))

				var sendWindowUpdated bool
				go func() {
					time.Sleep(2 * time.Millisecond)
					b = true
					sendWindowUpdated = str.connectionFlowController.UpdateSendWindow(3)
					str.ConnectionFlowControlWindowUpdated()
				}()

				n, err := str.Write([]byte{0x13, 0x37})
				Expect(b).To(BeTrue())
				Expect(sendWindowUpdated).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(3)))
				Expect(err).ToNot(HaveOccurred())
			})

			It("splits writing of frames when given more data than the flow control windows size", func() {
				updated := str.flowController.UpdateSendWindow(2)
				Expect(updated).To(BeTrue())
				var b bool

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(4)
				}()

				n, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.frames).To(HaveLen(2))
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(4))
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(4)))
			})

			It("writes after a flow control window update", func() {
				var b bool
				updated := str.flowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())

				_, err := str.Write([]byte{0x42})
				Expect(err).ToNot(HaveOccurred())

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.UpdateSendFlowControlWindow(3)
				}()
				n, err := str.Write([]byte{0xDE, 0xAD})
				Expect(err).ToNot(HaveOccurred())
				Expect(b).To(BeTrue())
				Expect(n).To(Equal(2))
				Expect(str.writeOffset).To(Equal(protocol.ByteCount(3)))
			})

			It("immediately returns on remote errors", func() {
				var b bool
				updated := str.flowController.UpdateSendWindow(1)
				Expect(updated).To(BeTrue())

				testErr := errors.New("test error")

				go func() {
					time.Sleep(time.Millisecond)
					b = true
					str.RegisterError(testErr)
				}()

				_, err := str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
				Expect(err).To(MatchError(testErr))
				Expect(b).To(BeTrue())
			})

			It("works with large flow control windows", func() {
				// This paniced before due to a wrong cast,
				// see https://github.com/lucas-clemente/quic-go/issues/143
				str.contributesToConnectionFlowControl = false
				updated := str.UpdateSendFlowControlWindow(protocol.ByteCount(1) << 63)
				Expect(updated).To(BeTrue())
				_, err := str.Write([]byte("foobar"))
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	PContext("Blocked streams", func() {
		It("notifies the session when a stream is flow control blocked", func() {
			updated := str.flowController.UpdateSendWindow(1337)
			Expect(updated).To(BeTrue())
			str.flowController.AddBytesSent(1337)
			str.maybeTriggerBlocked()
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})

		It("notifies the session as soon as a stream is reaching the end of the window", func() {
			updated := str.flowController.UpdateSendWindow(4)
			Expect(updated).To(BeTrue())
			str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})

		It("notifies the session as soon as a stream is flow control blocked", func() {
			updated := str.flowController.UpdateSendWindow(2)
			Expect(updated).To(BeTrue())
			go func() {
				str.Write([]byte{0xDE, 0xCA, 0xFB, 0xAD})
			}()
			time.Sleep(time.Millisecond)
			Expect(handler.receivedBlockedCalled).To(BeTrue())
			Expect(handler.receivedBlockedForStream).To(Equal(str.streamID))
		})
	})

	Context("flow control, for receiving", func() {
		BeforeEach(func() {
			str.flowControlManager = &mockFlowControlHandler{}
		})

		It("updates the highestReceived value in the flow controller", func() {
			frame := frames.StreamFrame{
				Offset: 2,
				Data:   []byte("foobar"),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			Expect(err).ToNot(HaveOccurred())
			Expect(str.flowControlManager.(*mockFlowControlHandler).highestReceivedForStream).To(Equal(str.streamID))
			Expect(str.flowControlManager.(*mockFlowControlHandler).highestReceived).To(Equal(protocol.ByteCount(2 + 6)))
		})

		It("updates the flow control window", func() {
			str.flowControlManager.(*mockFlowControlHandler).triggerStreamWindowUpdate = true
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte("foobar"),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(handler.receiveFlowControlWindowCalled).To(BeTrue())
			Expect(handler.receiveFlowControlWindowCalledForStream).To(Equal(str.streamID))
		})

		It("updates the connection level flow control window", func() {
			str.flowControlManager.(*mockFlowControlHandler).triggerConnectionWindowUpdate = true
			frame := frames.StreamFrame{
				Offset: 0,
				Data:   []byte("foobar"),
			}
			err := str.AddStreamFrame(&frame)
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(handler.receiveFlowControlWindowCalled).To(BeTrue())
			Expect(handler.receiveFlowControlWindowCalledForStream).To(Equal(protocol.StreamID(0)))
		})

		// TODO: think about flow control violation
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

		Context("when CloseRemote is called", func() {
			It("closes", func() {
				str.CloseRemote(0)
				b := make([]byte, 8)
				n, err := str.Read(b)
				Expect(n).To(BeZero())
				Expect(err).To(MatchError(io.EOF))
			})
		})
	})
})
