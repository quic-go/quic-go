package quic

import (
	"errors"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockFlowControlHandler struct {
	streamsContributing []protocol.StreamID

	sendWindowSizes               map[protocol.StreamID]protocol.ByteCount
	remainingConnectionWindowSize protocol.ByteCount
	bytesReadForStream            protocol.StreamID
	bytesRead                     protocol.ByteCount
	bytesSent                     protocol.ByteCount

	highestReceivedForStream protocol.StreamID
	highestReceived          protocol.ByteCount

	triggerStreamWindowUpdate     bool
	triggerConnectionWindowUpdate bool
}

func newMockFlowControlHandler() *mockFlowControlHandler {
	return &mockFlowControlHandler{
		sendWindowSizes: make(map[protocol.StreamID]protocol.ByteCount),
	}
}

func (m *mockFlowControlHandler) NewStream(streamID protocol.StreamID, contributesToConnectionFlow bool) {
	panic("not implemented")
}

func (m *mockFlowControlHandler) RemoveStream(streamID protocol.StreamID) {
	delete(m.sendWindowSizes, streamID)
}

func (m *mockFlowControlHandler) GetWindowUpdates() (res []flowcontrol.WindowUpdate) {
	if m.triggerStreamWindowUpdate {
		res = append(res, flowcontrol.WindowUpdate{StreamID: 42, Offset: 0x1337})
	}
	if m.triggerConnectionWindowUpdate {
		res = append(res, flowcontrol.WindowUpdate{StreamID: 0, Offset: 0x1337})
	}
	return res
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

func (m *mockFlowControlHandler) AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error {
	m.bytesSent += n
	m.sendWindowSizes[streamID] -= n
	for _, s := range m.streamsContributing {
		if s == streamID {
			m.remainingConnectionWindowSize -= n
			return nil
		}
	}
	return nil
}

func (m *mockFlowControlHandler) SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error) {
	res := m.sendWindowSizes[streamID]
	for _, s := range m.streamsContributing {
		if s == streamID {
			return utils.MinByteCount(res, m.remainingConnectionWindowSize), nil
		}
	}
	return res, nil
}

func (m *mockFlowControlHandler) RemainingConnectionWindowSize() protocol.ByteCount {
	return m.remainingConnectionWindowSize
}

func (m *mockFlowControlHandler) UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error) {
	panic("not implemented")
}

var _ = Describe("Stream", func() {
	var (
		str          *stream
		onDataCalled bool
	)

	onData := func() {
		onDataCalled = true
	}

	BeforeEach(func() {
		onDataCalled = false
		var streamID protocol.StreamID = 1337
		cpm := handshake.NewConnectionParamatersManager(protocol.VersionWhatever)
		flowControlManager := flowcontrol.NewFlowControlManager(cpm, &congestion.RTTStats{})
		flowControlManager.NewStream(streamID, true)
		str, _ = newStream(streamID, onData, flowControlManager)
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
			Expect(err).To(MatchError("OverlappingStreamData: start of gap in stream chunk"))
		})

		It("calls onData", func() {
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
	})

	Context("writing", func() {
		It("writes and gets all data at once", func(done Done) {
			go func() {
				n, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
			Expect(onDataCalled).To(BeTrue())
			Expect(str.lenOfDataForWriting()).To(Equal(protocol.ByteCount(6)))
			data := str.getDataForWriting(1000)
			Expect(data).To(Equal([]byte("foobar")))
			Expect(str.writeOffset).To(Equal(protocol.ByteCount(6)))
			Expect(str.dataForWriting).To(BeNil())
		})

		It("writes and gets data in two turns", func(done Done) {
			go func() {
				n, err := str.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				close(done)
			}()
			Eventually(func() []byte {
				str.mutex.Lock()
				defer str.mutex.Unlock()
				return str.dataForWriting
			}).Should(Equal([]byte("foobar")))
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
		})

		It("returns remote errors", func(done Done) {
			testErr := errors.New("test")
			str.RegisterError(testErr)
			n, err := str.Write([]byte("foo"))
			Expect(n).To(BeZero())
			Expect(err).To(MatchError(testErr))
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
	})

	Context("closing", func() {
		It("sets closed when calling Close", func() {
			str.Close()
			Expect(str.closed).ToNot(BeZero())
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
			str.RegisterError(errors.New("test"))
			Expect(str.shouldSendFin()).To(BeFalse())
		})

		It("does not allow FIN twice", func() {
			str.Close()
			Expect(str.shouldSendFin()).To(BeTrue())
			str.sentFin()
			Expect(str.shouldSendFin()).To(BeFalse())
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
