package quic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

type mockConnection struct {
	remoteAddr net.IP
	written    [][]byte
}

func (m *mockConnection) write(p []byte) error {
	b := make([]byte, len(p))
	copy(b, p)
	m.written = append(m.written, b)
	return nil
}

func (m *mockConnection) setCurrentRemoteAddr(addr interface{}) {
	if ip, ok := addr.(net.IP); ok {
		m.remoteAddr = ip
	}
}
func (*mockConnection) RemoteAddr() *net.UDPAddr { return &net.UDPAddr{} }

type mockUnpacker struct {
	unpackErr error
}

func (m *mockUnpacker) Unpack(publicHeaderBinary []byte, hdr *PublicHeader, data []byte) (*unpackedPacket, error) {
	if m.unpackErr != nil {
		return nil, m.unpackErr
	}
	return &unpackedPacket{
		frames: nil,
	}, nil
}

type mockSentPacketHandler struct {
	retransmissionQueue  []*ackhandler.Packet
	sentPackets          []*ackhandler.Packet
	congestionLimited    bool
	maybeQueueRTOsCalled bool
	requestedStopWaiting bool
}

func (h *mockSentPacketHandler) SentPacket(packet *ackhandler.Packet) error {
	h.sentPackets = append(h.sentPackets, packet)
	return nil
}
func (h *mockSentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, recvTime time.Time) error {
	return nil
}
func (h *mockSentPacketHandler) BytesInFlight() protocol.ByteCount      { return 0 }
func (h *mockSentPacketHandler) GetLeastUnacked() protocol.PacketNumber { return 1 }
func (h *mockSentPacketHandler) GetStopWaitingFrame(force bool) *frames.StopWaitingFrame {
	h.requestedStopWaiting = true
	return &frames.StopWaitingFrame{LeastUnacked: 0x1337}
}
func (h *mockSentPacketHandler) SendingAllowed() bool      { return !h.congestionLimited }
func (h *mockSentPacketHandler) CheckForError() error      { return nil }
func (h *mockSentPacketHandler) TimeOfFirstRTO() time.Time { panic("not implemented") }

func (h *mockSentPacketHandler) MaybeQueueRTOs() {
	h.maybeQueueRTOsCalled = true
}

func (h *mockSentPacketHandler) DequeuePacketForRetransmission() *ackhandler.Packet {
	if len(h.retransmissionQueue) > 0 {
		packet := h.retransmissionQueue[0]
		h.retransmissionQueue = h.retransmissionQueue[1:]
		return packet
	}
	return nil
}

func newMockSentPacketHandler() ackhandler.SentPacketHandler {
	return &mockSentPacketHandler{}
}

var _ ackhandler.SentPacketHandler = &mockSentPacketHandler{}

type mockReceivedPacketHandler struct {
	nextAckFrame *frames.AckFrame
}

func (m *mockReceivedPacketHandler) GetAckFrame() *frames.AckFrame { return m.nextAckFrame }
func (m *mockReceivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error {
	panic("not implemented")
}
func (m *mockReceivedPacketHandler) ReceivedStopWaiting(*frames.StopWaitingFrame) error {
	panic("not implemented")
}

var _ ackhandler.ReceivedPacketHandler = &mockReceivedPacketHandler{}

var _ = Describe("Session", func() {
	var (
		session              *Session
		streamCallbackCalled bool
		closeCallbackCalled  bool
		conn                 *mockConnection
		cpm                  *mockConnectionParametersManager
	)

	BeforeEach(func() {
		conn = &mockConnection{}
		streamCallbackCalled = false
		closeCallbackCalled = false

		signer, err := crypto.NewProofSource(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		kex, err := crypto.NewCurve25519KEX()
		Expect(err).NotTo(HaveOccurred())
		scfg, err := handshake.NewServerConfig(kex, signer)
		Expect(err).NotTo(HaveOccurred())
		pSession, err := newSession(
			conn,
			protocol.Version35,
			0,
			scfg,
			func(*Session, utils.Stream) { streamCallbackCalled = true },
			func(protocol.ConnectionID) { closeCallbackCalled = true },
		)
		Expect(err).NotTo(HaveOccurred())
		session = pSession.(*Session)
		Expect(session.streamsMap.openStreams).To(HaveLen(1)) // Crypto stream

		cpm = &mockConnectionParametersManager{idleTime: 60 * time.Second}
		session.connectionParameters = cpm
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			_, err := str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not reject existing streams with even StreamIDs", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			Expect(streamCallbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			p := make([]byte, 4)
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			_, err := str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not delete streams with Close()", func() {
			str, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
			session.garbageCollectStreams()
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ = session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
		})

		It("does not delete streams with FIN bit", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := str.Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ = session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
		})

		It("deletes streams with FIN bit & close", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := str.Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ = session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			// We still need to close the stream locally
			str.Close()
			// ... and simulate that we actually the FIN
			str.sentFin()
			session.garbageCollectStreams()
			Expect(session.streamsMap.openStreams).To(HaveLen(1))
			str, err = session.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
			// flow controller should have been notified
			_, err = session.flowControlManager.SendWindowSize(5)
			Expect(err).To(MatchError("Error accessing the flowController map."))
		})

		It("cancels streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = str.Read(p)
			Expect(err).To(MatchError(testErr))
			session.garbageCollectStreams()
			Expect(session.streamsMap.openStreams).To(BeEmpty())
			str, err = session.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("cancels empty streams with error", func() {
			testErr := errors.New("test")
			session.GetOrOpenStream(5)
			Expect(session.streamsMap.openStreams).To(HaveLen(2))
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			session.closeStreamsWithError(testErr)
			_, err := str.Read([]byte{0})
			Expect(err).To(MatchError(testErr))
			session.garbageCollectStreams()
			str, err = session.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("informs the FlowControlManager about new streams", func() {
			// since the stream doesn't yet exist, this will throw an error
			err := session.flowControlManager.UpdateHighestReceived(5, 1000)
			Expect(err).To(HaveOccurred())
			session.GetOrOpenStream(5)
			err = session.flowControlManager.UpdateHighestReceived(5, 2000)
			Expect(err).ToNot(HaveOccurred())
		})

		It("ignores streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			str, _ := session.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			_, err := str.Read([]byte{0})
			Expect(err).To(MatchError(io.EOF))
			str.Close()
			str.sentFin()
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(BeNil())
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the streams for writing", func() {
			s, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).ToNot(HaveOccurred())
			n, err := s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
		})

		It("doesn't close the stream for reading", func() {
			s, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			})
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ErrorCode:  42,
				ByteOffset: 6,
			})
			Expect(err).ToNot(HaveOccurred())
			b := make([]byte, 3)
			n, err := s.Read(b)
			Expect(n).To(Equal(3))
			Expect(err).ToNot(HaveOccurred())
		})

		It("queues a RST_STERAM frame with the correct offset", func() {
			str, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.(*stream).writeOffset = 0x1337
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID: 5,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.packer.controlFrames).To(HaveLen(1))
			Expect(session.packer.controlFrames[0].(*frames.RstStreamFrame)).To(Equal(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			}))
			Expect(str.(*stream).finished()).To(BeTrue())
		})

		It("doesn't queue a RST_STREAM for a stream that it already sent a FIN on", func() {
			str, err := session.GetOrOpenStream(5)
			str.(*stream).sentFin()
			str.Close()
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID: 5,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.packer.controlFrames).To(BeEmpty())
			Expect(str.(*stream).finished()).To(BeTrue())
		})

		It("passes the byte offset to the flow controller", func() {
			session.streamsMap.GetOrOpenStream(5)
			session.flowControlManager = newMockFlowControlHandler()
			err := session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.flowControlManager.(*mockFlowControlHandler).highestReceivedForStream).To(Equal(protocol.StreamID(5)))
			Expect(session.flowControlManager.(*mockFlowControlHandler).highestReceived).To(Equal(protocol.ByteCount(0x1337)))
		})

		It("returns errors from the flow controller", func() {
			session.streamsMap.GetOrOpenStream(5)
			session.flowControlManager = newMockFlowControlHandler()
			testErr := errors.New("flow control violation")
			session.flowControlManager.(*mockFlowControlHandler).flowControlViolation = testErr
			err := session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			})
			Expect(err).To(MatchError(testErr))
		})

		It("ignores the error when the stream is not known", func() {
			err := session.handleFrames([]frames.Frame{&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			}})
			Expect(err).NotTo(HaveOccurred())
		})

		It("queues a RST_STREAM when a stream gets reset locally", func() {
			testErr := errors.New("testErr")
			str, err := session.streamsMap.GetOrOpenStream(5)
			str.writeOffset = 0x1337
			Expect(err).ToNot(HaveOccurred())
			str.Reset(testErr)
			Expect(session.packer.controlFrames).To(HaveLen(1))
			Expect(session.packer.controlFrames[0]).To(Equal(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			}))
			Expect(str.finished()).To(BeFalse())
		})

		It("doesn't queue another RST_STREAM, when it receives an RST_STREAM as a response for the first", func() {
			testErr := errors.New("testErr")
			str, err := session.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Reset(testErr)
			Expect(session.packer.controlFrames).To(HaveLen(1))
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x42,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.packer.controlFrames).To(HaveLen(1))
		})
	})

	Context("handling WINDOW_UPDATE frames", func() {
		It("updates the Flow Control Window of a stream", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 100,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.flowControlManager.SendWindowSize(5)).To(Equal(protocol.ByteCount(100)))
		})

		It("updates the Flow Control Window of the connection", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   0,
				ByteOffset: 0x800000,
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("opens a new stream when receiving a WINDOW_UPDATE for an unknown stream", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).ToNot(HaveOccurred())
			str, err := session.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).ToNot(BeNil())
		})

		It("errors when receiving a WindowUpdateFrame for a closed stream", func() {
			session.handleStreamFrame(&frames.StreamFrame{StreamID: 5})
			err := session.streamsMap.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			session.garbageCollectStreams()
			err = session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnClosedStream))
		})

		It("ignores errors when receiving a WindowUpdateFrame for a closed stream", func() {
			session.handleStreamFrame(&frames.StreamFrame{StreamID: 5})
			err := session.streamsMap.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			session.garbageCollectStreams()
			err = session.handleFrames([]frames.Frame{&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			}})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("handles PING frames", func() {
		err := session.handleFrames([]frames.Frame{&frames.PingFrame{}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles BLOCKED frames", func() {
		err := session.handleFrames([]frames.Frame{&frames.BlockedFrame{}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("errors on GOAWAY frames", func() {
		err := session.handleFrames([]frames.Frame{&frames.GoawayFrame{}})
		Expect(err).To(MatchError("unimplemented: handling GOAWAY frames"))
	})

	It("handles STOP_WAITING frames", func() {
		err := session.handleFrames([]frames.Frame{&frames.StopWaitingFrame{LeastUnacked: 10}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles CONNECTION_CLOSE frames", func() {
		str, _ := session.GetOrOpenStream(5)
		err := session.handleFrames([]frames.Frame{&frames.ConnectionCloseFrame{ErrorCode: 42, ReasonPhrase: "foobar"}})
		Expect(err).NotTo(HaveOccurred())
		_, err = str.Read([]byte{0})
		Expect(err).To(MatchError(qerr.Error(42, "foobar")))
	})

	Context("closing", func() {
		var (
			nGoRoutinesBefore int
		)

		BeforeEach(func() {
			time.Sleep(10 * time.Millisecond) // Wait for old goroutines to finish
			nGoRoutinesBefore = runtime.NumGoroutine()
			go session.run()
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore + 2))
		})

		It("shuts down without error", func() {
			session.Close(nil)
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0][len(conn.written[0])-7:]).To(Equal([]byte{0x02, byte(qerr.PeerGoingAway), 0, 0, 0, 0, 0}))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(session.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})

		It("only closes once", func() {
			session.Close(nil)
			session.Close(nil)
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			Expect(conn.written).To(HaveLen(1))
			Expect(session.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := session.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			session.Close(testErr)
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			Expect(closeCallbackCalled).To(BeTrue())
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			Expect(session.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})
	})

	Context("receiving packets", func() {
		var hdr *PublicHeader

		BeforeEach(func() {
			session.unpacker = &mockUnpacker{}
			hdr = &PublicHeader{PacketNumberLen: protocol.PacketNumberLen6}
		})

		It("sets the {last,largest}RcvdPacketNumber", func() {
			hdr.PacketNumber = 5
			err := session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(session.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("sets the {last,largest}RcvdPacketNumber, for an out-of-order packet", func() {
			hdr.PacketNumber = 5
			err := session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(session.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			hdr.PacketNumber = 3
			err = session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(session.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("ignores duplicate packets", func() {
			hdr.PacketNumber = 5
			err := session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			err = session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		It("ignores packets smaller than the highest LeastUnacked of a StopWaiting", func() {
			err := session.receivedPacketHandler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			hdr.PacketNumber = 5
			err = session.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		Context("updating the remote address", func() {
			It("sets the remote address", func() {
				remoteIP := net.IPv4(192, 168, 0, 100)
				Expect(session.conn.(*mockConnection).remoteAddr).ToNot(Equal(remoteIP))
				p := receivedPacket{
					remoteAddr:   remoteIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				err := session.handlePacketImpl(&p)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})

			It("doesn't change the remote address if authenticating the packet fails", func() {
				remoteIP := net.IPv4(192, 168, 0, 100)
				attackerIP := net.IPv4(192, 168, 0, 102)
				session.conn.(*mockConnection).remoteAddr = remoteIP
				// use the real packetUnpacker here, to make sure this test fails if the error code for failed decryption changes
				session.unpacker = &packetUnpacker{}
				session.unpacker.(*packetUnpacker).aead = &crypto.NullAEAD{}
				p := receivedPacket{
					remoteAddr:   attackerIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				err := session.handlePacketImpl(&p)
				quicErr := err.(*qerr.QuicError)
				Expect(quicErr.ErrorCode).To(Equal(qerr.DecryptionFailure))
				Expect(session.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})

			It("sets the remote address, if the packet is authenticated, but unpacking fails for another reason", func() {
				testErr := errors.New("testErr")
				remoteIP := net.IPv4(192, 168, 0, 100)
				Expect(session.conn.(*mockConnection).remoteAddr).ToNot(Equal(remoteIP))
				p := receivedPacket{
					remoteAddr:   remoteIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				session.unpacker.(*mockUnpacker).unpackErr = testErr
				err := session.handlePacketImpl(&p)
				Expect(err).To(MatchError(testErr))
				Expect(session.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})
		})
	})

	Context("sending packets", func() {
		It("sends ack frames", func() {
			packetNumber := protocol.PacketNumber(0x035E)
			session.receivedPacketHandler.ReceivedPacket(packetNumber, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x5E, 0x03})))
		})

		It("sends two WindowUpdate frames", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			session.flowControlManager.AddBytesRead(5, protocol.ReceiveStreamFlowControlWindow)
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(2))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
			Expect(conn.written[1]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
		})

		It("sends public reset", func() {
			err := session.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		})
	})

	Context("retransmissions", func() {
		It("sends a StreamFrame from a packet queued for retransmission", func() {
			// a StopWaitingFrame is added, so make sure the packet number of the new package is higher than the packet number of the retransmitted packet
			session.packer.packetNumberGenerator.next = 0x1337 + 9

			f := frames.StreamFrame{
				StreamID: 0x5,
				Data:     []byte("foobar1234567"),
			}
			p := ackhandler.Packet{
				PacketNumber: 0x1337,
				Frames:       []frames.Frame{&f},
			}
			sph := newMockSentPacketHandler()
			sph.(*mockSentPacketHandler).retransmissionQueue = []*ackhandler.Packet{&p}
			session.sentPacketHandler = sph

			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(sph.(*mockSentPacketHandler).requestedStopWaiting).To(BeTrue())
			Expect(conn.written[0]).To(ContainSubstring("foobar1234567"))
		})

		It("sends a StreamFrame from a packet queued for retransmission", func() {
			// a StopWaitingFrame is added, so make sure the packet number of the new package is higher than the packet number of the retransmitted packet
			session.packer.packetNumberGenerator.next = 0x1337 + 9

			f1 := frames.StreamFrame{
				StreamID: 0x5,
				Data:     []byte("foobar"),
			}
			f2 := frames.StreamFrame{
				StreamID: 0x7,
				Data:     []byte("loremipsum"),
			}
			p1 := ackhandler.Packet{
				PacketNumber: 0x1337,
				Frames:       []frames.Frame{&f1},
			}
			p2 := ackhandler.Packet{
				PacketNumber: 0x1338,
				Frames:       []frames.Frame{&f2},
			}
			sph := newMockSentPacketHandler()
			sph.(*mockSentPacketHandler).retransmissionQueue = []*ackhandler.Packet{&p1, &p2}
			session.sentPacketHandler = sph

			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring("foobar"))
			Expect(conn.written[0]).To(ContainSubstring("loremipsum"))
		})

		It("always attaches a StopWaiting to a packet that contains a retransmission", func() {
			// make sure the packet number of the new package is higher than the packet number of the retransmitted packet
			session.packer.packetNumberGenerator.next = 0x1337 + 9

			f := &frames.StreamFrame{
				StreamID: 0x5,
				Data:     bytes.Repeat([]byte{'f'}, int(1.5*float32(protocol.MaxPacketSize))),
			}
			session.streamFramer.AddFrameForRetransmission(f)

			sph := newMockSentPacketHandler()
			session.sentPacketHandler = sph

			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(2))
			sentPackets := sph.(*mockSentPacketHandler).sentPackets
			Expect(sentPackets).To(HaveLen(2))
			_, ok := sentPackets[0].Frames[0].(*frames.StopWaitingFrame)
			Expect(ok).To(BeTrue())
			_, ok = sentPackets[1].Frames[0].(*frames.StopWaitingFrame)
			Expect(ok).To(BeTrue())
		})

		It("calls MaybeQueueRTOs even if congestion blocked, so that bytesInFlight is updated", func() {
			sph := newMockSentPacketHandler()
			sph.(*mockSentPacketHandler).congestionLimited = true
			session.sentPacketHandler = sph
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sph.(*mockSentPacketHandler).maybeQueueRTOsCalled).To(BeTrue())
		})

		It("retransmits a WindowUpdates if it hasn't already sent a WindowUpdate with a higher ByteOffset", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			fc := newMockFlowControlHandler()
			fc.receiveWindow = 0x1000
			session.flowControlManager = fc
			sph := newMockSentPacketHandler()
			session.sentPacketHandler = sph
			wuf := &frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 0x1000,
			}
			sph.(*mockSentPacketHandler).retransmissionQueue = []*ackhandler.Packet{{
				Frames: []frames.Frame{wuf},
			}}
			err = session.sendPacket()
			Expect(err).ToNot(HaveOccurred())
			sentPackets := sph.(*mockSentPacketHandler).sentPackets
			Expect(sentPackets).To(HaveLen(1))
			Expect(sentPackets[0].Frames).To(ContainElement(wuf))
		})

		It("doesn't retransmit WindowUpdates if it already sent a WindowUpdate with a higher ByteOffset", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			fc := newMockFlowControlHandler()
			fc.receiveWindow = 0x2000
			session.flowControlManager = fc
			sph := newMockSentPacketHandler()
			session.sentPacketHandler = sph
			sph.(*mockSentPacketHandler).retransmissionQueue = []*ackhandler.Packet{{
				Frames: []frames.Frame{&frames.WindowUpdateFrame{
					StreamID:   5,
					ByteOffset: 0x1000,
				}},
			}}
			err = session.sendPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(sph.(*mockSentPacketHandler).sentPackets).To(BeEmpty())
		})

		It("doesn't retransmit WindowUpdates for closed streams", func() {
			str, err := session.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			// close the stream
			str.(*stream).sentFin()
			str.Close()
			str.(*stream).RegisterRemoteError(nil)
			session.garbageCollectStreams()
			_, err = session.flowControlManager.SendWindowSize(5)
			Expect(err).To(MatchError("Error accessing the flowController map."))
			sph := newMockSentPacketHandler()
			session.sentPacketHandler = sph
			sph.(*mockSentPacketHandler).retransmissionQueue = []*ackhandler.Packet{{
				Frames: []frames.Frame{&frames.WindowUpdateFrame{
					StreamID:   5,
					ByteOffset: 0x1337,
				}},
			}}
			err = session.sendPacket()
			Expect(err).ToNot(HaveOccurred())
			sentPackets := sph.(*mockSentPacketHandler).sentPackets
			Expect(sentPackets).To(BeEmpty())
		})
	})

	Context("scheduling sending", func() {
		It("sends after writing to a stream", func(done Done) {
			Expect(session.sendingScheduled).NotTo(Receive())
			s, err := session.GetOrOpenStream(3)
			Expect(err).NotTo(HaveOccurred())
			go func() {
				s.Write([]byte("foobar"))
				close(done)
			}()
			Eventually(session.sendingScheduled).Should(Receive())
			s.(*stream).getDataForWriting(1000) // unblock
		})

		It("sets the timer to the ack timer", func() {
			rph := &mockReceivedPacketHandler{}
			rph.nextAckFrame = &frames.AckFrame{LargestAcked: 0x1337}
			session.receivedPacketHandler = rph
			go session.run()
			session.ackAlarmChanged(time.Now().Add(10 * time.Millisecond))
			time.Sleep(10 * time.Millisecond)
			Eventually(func() int { return len(conn.written) }).ShouldNot(BeZero())
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x37, 0x13})))
		})

		Context("bundling of small packets", func() {
			It("bundles two small frames of different streams into one packet", func() {
				s1, err := session.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				s2, err := session.GetOrOpenStream(7)
				Expect(err).NotTo(HaveOccurred())

				// Put data directly into the streams
				s1.(*stream).dataForWriting = []byte("foobar1")
				s2.(*stream).dataForWriting = []byte("foobar2")

				session.scheduleSending()
				go session.run()

				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(1))
				Expect(conn.written[0]).To(ContainSubstring("foobar1"))
				Expect(conn.written[0]).To(ContainSubstring("foobar2"))
			})

			It("sends out two big frames in two packets", func() {
				s1, err := session.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				s2, err := session.GetOrOpenStream(7)
				Expect(err).NotTo(HaveOccurred())
				go session.run()
				go func() {
					defer GinkgoRecover()
					_, err2 := s1.Write(bytes.Repeat([]byte{'e'}, 1000))
					Expect(err2).ToNot(HaveOccurred())
				}()
				_, err = s2.Write(bytes.Repeat([]byte{'e'}, 1000))
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(2))
			})

			It("sends out two small frames that are written to long after one another into two packets", func() {
				s, err := session.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				go session.run()
				_, err = s.Write([]byte("foobar1"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(2))
			})

			It("sends a queued ACK frame only once", func() {
				packetNumber := protocol.PacketNumber(0x1337)
				session.receivedPacketHandler.ReceivedPacket(packetNumber, true)

				s, err := session.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				go session.run()
				_, err = s.Write([]byte("foobar1"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() [][]byte { return conn.written }).Should(HaveLen(2))
				Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x37, 0x13})))
				Expect(conn.written[1]).ToNot(ContainSubstring(string([]byte{0x37, 0x13})))
			})
		})
	})

	It("closes when crypto stream errors", func() {
		go session.run()
		s, err := session.GetOrOpenStream(3)
		Expect(err).NotTo(HaveOccurred())
		err = session.handleStreamFrame(&frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("4242\x00\x00\x00\x00"),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool { return atomic.LoadUint32(&session.closed) != 0 }).Should(BeTrue())
		_, err = s.Write([]byte{})
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidCryptoMessageType))
	})

	It("sends public reset after too many undecryptable packets", func() {
		// Write protocol.MaxUndecryptablePackets and expect a public reset to happen
		for i := 0; i < protocol.MaxUndecryptablePackets; i++ {
			hdr := &PublicHeader{
				PacketNumber: protocol.PacketNumber(i + 1),
			}
			session.handlePacket(&receivedPacket{publicHeader: hdr, data: []byte("foobar")})
		}
		session.run()

		Expect(conn.written).To(HaveLen(1))
		Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		Expect(session.runClosed).To(Receive())
	})

	It("ignores undecryptable packets after the handshake is complete", func() {
		*(*bool)(unsafe.Pointer(reflect.ValueOf(session.cryptoSetup).Elem().FieldByName("receivedForwardSecurePacket").UnsafeAddr())) = true
		for i := 0; i < protocol.MaxUndecryptablePackets; i++ {
			hdr := &PublicHeader{
				PacketNumber: protocol.PacketNumber(i + 1),
			}
			session.handlePacket(&receivedPacket{publicHeader: hdr, data: []byte("foobar")})
		}
		go session.run()
		Consistently(session.undecryptablePackets).Should(HaveLen(0))
		session.closeImpl(nil, true)
		Eventually(session.runClosed).Should(Receive())
	})

	It("unqueues undecryptable packets for later decryption", func() {
		session.undecryptablePackets = []*receivedPacket{{
			publicHeader: &PublicHeader{PacketNumber: protocol.PacketNumber(42)},
		}}
		Expect(session.receivedPackets).NotTo(Receive())
		session.tryDecryptingQueuedPackets()
		Expect(session.undecryptablePackets).To(BeEmpty())
		Expect(session.receivedPackets).To(Receive())
	})

	Context("timeouts", func() {
		It("times out due to no network activity", func(done Done) {
			session.lastNetworkActivityTime = time.Now().Add(-time.Hour)
			session.run() // Would normally not return
			Expect(conn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(session.runClosed).To(Receive())
			close(done)
		})

		It("times out due to non-completed crypto handshake", func(done Done) {
			session.sessionCreationTime = time.Now().Add(-time.Hour)
			session.run() // Would normally not return
			Expect(conn.written[0]).To(ContainSubstring("Crypto handshake did not complete in time."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(session.runClosed).To(Receive())
			close(done)
		})

		It("does not use ICSL before handshake", func(done Done) {
			session.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			cpm.idleTime = 99999 * time.Second
			session.packer.connectionParameters = session.connectionParameters
			session.run() // Would normally not return
			Expect(conn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(session.runClosed).To(Receive())
			close(done)
		})

		It("uses ICSL after handshake", func(done Done) {
			// session.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			*(*bool)(unsafe.Pointer(reflect.ValueOf(session.cryptoSetup).Elem().FieldByName("receivedForwardSecurePacket").UnsafeAddr())) = true
			*(*crypto.AEAD)(unsafe.Pointer(reflect.ValueOf(session.cryptoSetup).Elem().FieldByName("forwardSecureAEAD").UnsafeAddr())) = &crypto.NullAEAD{}
			cpm.idleTime = 0 * time.Millisecond
			session.packer.connectionParameters = session.connectionParameters
			session.run() // Would normally not return
			Expect(conn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(session.runClosed).To(Receive())
			close(done)
		})
	})

	It("errors when the SentPacketHandler has too many packets tracked", func() {
		streamFrame := frames.StreamFrame{StreamID: 5, Data: []byte("foobar")}
		for i := protocol.PacketNumber(1); i < protocol.MaxTrackedSentPackets+10; i++ {
			packet := ackhandler.Packet{PacketNumber: protocol.PacketNumber(i), Frames: []frames.Frame{&streamFrame}, Length: 1}
			err := session.sentPacketHandler.SentPacket(&packet)
			Expect(err).ToNot(HaveOccurred())
		}
		// now session.sentPacketHandler.CheckForError will return an error
		err := session.sendPacket()
		Expect(err).To(MatchError(ackhandler.ErrTooManyTrackedSentPackets))
	})

	It("stores up to MaxSessionUnprocessedPackets packets", func(done Done) {
		// Nothing here should block
		for i := protocol.PacketNumber(0); i < protocol.MaxSessionUnprocessedPackets+10; i++ {
			session.handlePacket(&receivedPacket{})
		}
		close(done)
	}, 0.5)

	It("retransmits RTO packets", func() {
		// We simulate consistently low RTTs, so that the test works faster
		n := protocol.PacketNumber(10)
		for p := protocol.PacketNumber(1); p < n; p++ {
			err := session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: p, Length: 1})
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(time.Microsecond)
			ack := &frames.AckFrame{}
			ack.LargestAcked = p
			err = session.sentPacketHandler.ReceivedAck(ack, p, time.Now())
			Expect(err).NotTo(HaveOccurred())
		}
		session.packer.packetNumberGenerator.next = n + 1
		// Now, we send a single packet, and expect that it was retransmitted later
		err := session.sentPacketHandler.SentPacket(&ackhandler.Packet{
			PacketNumber: n,
			Length:       1,
			Frames: []frames.Frame{&frames.StreamFrame{
				Data: []byte("foobar"),
			}},
		})
		Expect(err).NotTo(HaveOccurred())
		go session.run()
		session.scheduleSending()
		Eventually(func() [][]byte { return conn.written }).ShouldNot(BeEmpty())
		Expect(conn.written[0]).To(ContainSubstring("foobar"))
	})

	Context("counting streams", func() {
		It("errors when too many streams are opened", func() {
			for i := 2; i <= 110; i++ {
				_, err := session.GetOrOpenStream(protocol.StreamID(i*2 + 1))
				Expect(err).NotTo(HaveOccurred())
			}
			_, err := session.GetOrOpenStream(protocol.StreamID(301))
			Expect(err).To(MatchError(qerr.TooManyOpenStreams))
		})

		It("does not error when many streams are opened and closed", func() {
			for i := 2; i <= 1000; i++ {
				s, err := session.GetOrOpenStream(protocol.StreamID(i*2 + 1))
				Expect(err).NotTo(HaveOccurred())
				err = s.Close()
				Expect(err).NotTo(HaveOccurred())
				s.(*stream).sentFin()
				s.CloseRemote(0)
				_, err = s.Read([]byte("a"))
				Expect(err).To(MatchError(io.EOF))
				session.garbageCollectStreams()
			}
		})
	})

	Context("ignoring errors", func() {
		It("ignores duplicate acks", func() {
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{
				PacketNumber: 1,
				Length:       1,
			})
			err := session.handleFrames([]frames.Frame{&frames.AckFrame{
				LargestAcked: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
			err = session.handleFrames([]frames.Frame{&frames.AckFrame{
				LargestAcked: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("window updates", func() {
		It("gets stream level window updates", func() {
			err := session.flowControlManager.AddBytesRead(1, protocol.ReceiveStreamFlowControlWindow)
			Expect(err).NotTo(HaveOccurred())
			frames, err := session.getWindowUpdateFrames()
			Expect(err).NotTo(HaveOccurred())
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frames[0].ByteOffset).To(Equal(protocol.ReceiveStreamFlowControlWindow * 2))
		})

		It("gets connection level window updates", func() {
			_, err := session.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			err = session.flowControlManager.AddBytesRead(5, protocol.ReceiveConnectionFlowControlWindow)
			Expect(err).NotTo(HaveOccurred())
			frames, err := session.getWindowUpdateFrames()
			Expect(err).NotTo(HaveOccurred())
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].StreamID).To(Equal(protocol.StreamID(0)))
			Expect(frames[0].ByteOffset).To(Equal(protocol.ReceiveConnectionFlowControlWindow * 2))
		})
	})
})
