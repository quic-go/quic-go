package quic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime/pprof"
	"strings"
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
)

type mockConnection struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	written    [][]byte
}

func (m *mockConnection) Write(p []byte) error {
	b := make([]byte, len(p))
	copy(b, p)
	m.written = append(m.written, b)
	return nil
}
func (m *mockConnection) Read([]byte) (int, net.Addr, error) { panic("not implemented") }

func (m *mockConnection) SetCurrentRemoteAddr(addr net.Addr) {
	m.remoteAddr = addr
}
func (m *mockConnection) LocalAddr() net.Addr  { return m.localAddr }
func (m *mockConnection) RemoteAddr() net.Addr { return m.remoteAddr }
func (*mockConnection) Close() error           { panic("not implemented") }

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
	requestedStopWaiting bool
}

func (h *mockSentPacketHandler) SentPacket(packet *ackhandler.Packet) error {
	h.sentPackets = append(h.sentPackets, packet)
	return nil
}

func (h *mockSentPacketHandler) ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, recvTime time.Time) error {
	return nil
}

func (h *mockSentPacketHandler) GetLeastUnacked() protocol.PacketNumber { return 1 }
func (h *mockSentPacketHandler) GetAlarmTimeout() time.Time             { panic("not implemented") }
func (h *mockSentPacketHandler) OnAlarm()                               { panic("not implemented") }
func (h *mockSentPacketHandler) SendingAllowed() bool                   { return !h.congestionLimited }

func (h *mockSentPacketHandler) GetStopWaitingFrame(force bool) *frames.StopWaitingFrame {
	h.requestedStopWaiting = true
	return &frames.StopWaitingFrame{LeastUnacked: 0x1337}
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

func areSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*session).run")
}

var _ = Describe("Session", func() {
	var (
		sess                *session
		clientSess          *session
		closeCallbackCalled bool
		scfg                *handshake.ServerConfig
		mconn               *mockConnection
		cpm                 *mockConnectionParametersManager
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		mconn = &mockConnection{
			remoteAddr: &net.UDPAddr{},
		}
		closeCallbackCalled = false

		certChain := crypto.NewCertChain(testdata.GetTLSConfig())
		kex, err := crypto.NewCurve25519KEX()
		Expect(err).NotTo(HaveOccurred())
		scfg, err = handshake.NewServerConfig(kex, certChain)
		Expect(err).NotTo(HaveOccurred())
		pSess, err := newSession(
			mconn,
			protocol.Version35,
			0,
			scfg,
			func(protocol.ConnectionID) { closeCallbackCalled = true },
			func(Session, bool) {},
		)
		Expect(err).NotTo(HaveOccurred())
		sess = pSess.(*session)
		Expect(sess.streamsMap.openStreams).To(HaveLen(1)) // Crypto stream

		cpm = &mockConnectionParametersManager{idleTime: 60 * time.Second}
		sess.connectionParameters = cpm

		clientSess, err = newClientSession(
			nil,
			"hostname",
			protocol.Version35,
			0,
			nil,
			func(protocol.ConnectionID) { closeCallbackCalled = true },
			func(Session, bool) {},
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(clientSess.streamsMap.openStreams).To(HaveLen(1)) // Crypto stream
	})

	AfterEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("source address", func() {
		It("uses the IP address if given an UDP connection", func() {
			conn := &conn{currentAddr: &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200)[12:], Port: 1337}}
			sess, err := newSession(
				conn,
				protocol.VersionWhatever,
				0,
				scfg,
				func(protocol.ConnectionID) { closeCallbackCalled = true },
				func(Session, bool) {},
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(*(*[]byte)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("sourceAddr").UnsafeAddr()))).To(Equal([]byte{192, 168, 100, 200}))
		})

		It("uses the string representation of the remote addresses if not given a UDP connection", func() {
			conn := &conn{
				currentAddr: &net.TCPAddr{IP: net.IPv4(192, 168, 100, 200)[12:], Port: 1337},
			}
			sess, err := newSession(
				conn,
				protocol.VersionWhatever,
				0,
				scfg,
				func(protocol.ConnectionID) { closeCallbackCalled = true },
				func(Session, bool) {},
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(*(*[]byte)(unsafe.Pointer(reflect.ValueOf(sess.(*session).cryptoSetup).Elem().FieldByName("sourceAddr").UnsafeAddr()))).To(Equal([]byte("192.168.100.200:1337")))
		})
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			p := make([]byte, 4)
			str, err := sess.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
			_, err = str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not reject existing streams with even StreamIDs", func() {
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("handles existing streams", func() {
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			numOpenStreams := len(sess.streamsMap.openStreams)
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(sess.streamsMap.openStreams).To(HaveLen(numOpenStreams))
			p := make([]byte, 4)
			str, _ := sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			_, err := str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not delete streams with Close()", func() {
			str, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
			sess.garbageCollectStreams()
			str, err = sess.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
		})

		It("does not delete streams with FIN bit", func() {
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			numOpenStreams := len(sess.streamsMap.openStreams)
			str, _ := sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			p := make([]byte, 4)
			_, err := str.Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			sess.garbageCollectStreams()
			Expect(sess.streamsMap.openStreams).To(HaveLen(numOpenStreams))
			str, _ = sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
		})

		It("deletes streams with FIN bit & close", func() {
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			numOpenStreams := len(sess.streamsMap.openStreams)
			str, _ := sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			p := make([]byte, 4)
			_, err := str.Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			sess.garbageCollectStreams()
			Expect(sess.streamsMap.openStreams).To(HaveLen(numOpenStreams))
			str, _ = sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			// We still need to close the stream locally
			str.Close()
			// ... and simulate that we actually the FIN
			str.sentFin()
			sess.garbageCollectStreams()
			Expect(len(sess.streamsMap.openStreams)).To(BeNumerically("<", numOpenStreams))
			str, err = sess.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
			// flow controller should have been notified
			_, err = sess.flowControlManager.SendWindowSize(5)
			Expect(err).To(MatchError("Error accessing the flowController map."))
		})

		It("cancels streams with error", func() {
			sess.garbageCollectStreams()
			testErr := errors.New("test")
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			str, err := sess.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
			p := make([]byte, 4)
			_, err = str.Read(p)
			Expect(err).ToNot(HaveOccurred())
			sess.closeStreamsWithError(testErr)
			_, err = str.Read(p)
			Expect(err).To(MatchError(testErr))
			sess.garbageCollectStreams()
			str, err = sess.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("cancels empty streams with error", func() {
			testErr := errors.New("test")
			sess.GetOrOpenStream(5)
			str, err := sess.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
			sess.closeStreamsWithError(testErr)
			_, err = str.Read([]byte{0})
			Expect(err).To(MatchError(testErr))
			sess.garbageCollectStreams()
			str, err = sess.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).To(BeNil())
		})

		It("informs the FlowControlManager about new streams", func() {
			// since the stream doesn't yet exist, this will throw an error
			err := sess.flowControlManager.UpdateHighestReceived(5, 1000)
			Expect(err).To(HaveOccurred())
			sess.GetOrOpenStream(5)
			err = sess.flowControlManager.UpdateHighestReceived(5, 2000)
			Expect(err).ToNot(HaveOccurred())
		})

		It("ignores streams that existed previously", func() {
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			str, _ := sess.streamsMap.GetOrOpenStream(5)
			Expect(str).ToNot(BeNil())
			_, err := str.Read([]byte{0})
			Expect(err).To(MatchError(io.EOF))
			str.Close()
			str.sentFin()
			sess.garbageCollectStreams()
			err = sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(BeNil())
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the streams for writing", func() {
			s, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).ToNot(HaveOccurred())
			n, err := s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
		})

		It("doesn't close the stream for reading", func() {
			s, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			})
			err = sess.handleRstStreamFrame(&frames.RstStreamFrame{
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
			str, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.(*stream).writeOffset = 0x1337
			err = sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID: 5,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.packer.controlFrames).To(HaveLen(1))
			Expect(sess.packer.controlFrames[0].(*frames.RstStreamFrame)).To(Equal(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			}))
			Expect(str.(*stream).finished()).To(BeTrue())
		})

		It("doesn't queue a RST_STREAM for a stream that it already sent a FIN on", func() {
			str, err := sess.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			str.(*stream).sentFin()
			str.Close()
			err = sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID: 5,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.packer.controlFrames).To(BeEmpty())
			Expect(str.(*stream).finished()).To(BeTrue())
		})

		It("passes the byte offset to the flow controller", func() {
			sess.streamsMap.GetOrOpenStream(5)
			sess.flowControlManager = newMockFlowControlHandler()
			err := sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.flowControlManager.(*mockFlowControlHandler).highestReceivedForStream).To(Equal(protocol.StreamID(5)))
			Expect(sess.flowControlManager.(*mockFlowControlHandler).highestReceived).To(Equal(protocol.ByteCount(0x1337)))
		})

		It("returns errors from the flow controller", func() {
			sess.streamsMap.GetOrOpenStream(5)
			sess.flowControlManager = newMockFlowControlHandler()
			testErr := errors.New("flow control violation")
			sess.flowControlManager.(*mockFlowControlHandler).flowControlViolation = testErr
			err := sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			})
			Expect(err).To(MatchError(testErr))
		})

		It("ignores the error when the stream is not known", func() {
			err := sess.handleFrames([]frames.Frame{&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			}})
			Expect(err).NotTo(HaveOccurred())
		})

		It("queues a RST_STREAM when a stream gets reset locally", func() {
			testErr := errors.New("testErr")
			str, err := sess.streamsMap.GetOrOpenStream(5)
			str.writeOffset = 0x1337
			Expect(err).ToNot(HaveOccurred())
			str.Reset(testErr)
			Expect(sess.packer.controlFrames).To(HaveLen(1))
			Expect(sess.packer.controlFrames[0]).To(Equal(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x1337,
			}))
			Expect(str.finished()).To(BeFalse())
		})

		It("doesn't queue another RST_STREAM, when it receives an RST_STREAM as a response for the first", func() {
			testErr := errors.New("testErr")
			str, err := sess.streamsMap.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Reset(testErr)
			Expect(sess.packer.controlFrames).To(HaveLen(1))
			err = sess.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:   5,
				ByteOffset: 0x42,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.packer.controlFrames).To(HaveLen(1))
		})
	})

	Context("handling WINDOW_UPDATE frames", func() {
		It("updates the Flow Control Window of a stream", func() {
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = sess.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 100,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.flowControlManager.SendWindowSize(5)).To(Equal(protocol.ByteCount(100)))
		})

		It("updates the Flow Control Window of the connection", func() {
			err := sess.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   0,
				ByteOffset: 0x800000,
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("opens a new stream when receiving a WINDOW_UPDATE for an unknown stream", func() {
			err := sess.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.streamsMap.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			Expect(str).ToNot(BeNil())
		})

		It("errors when receiving a WindowUpdateFrame for a closed stream", func() {
			sess.handleStreamFrame(&frames.StreamFrame{StreamID: 5})
			err := sess.streamsMap.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			sess.garbageCollectStreams()
			err = sess.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnClosedStream))
		})

		It("ignores errors when receiving a WindowUpdateFrame for a closed stream", func() {
			sess.handleStreamFrame(&frames.StreamFrame{StreamID: 5})
			err := sess.streamsMap.RemoveStream(5)
			Expect(err).ToNot(HaveOccurred())
			sess.garbageCollectStreams()
			err = sess.handleFrames([]frames.Frame{&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			}})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("handles PING frames", func() {
		err := sess.handleFrames([]frames.Frame{&frames.PingFrame{}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles BLOCKED frames", func() {
		err := sess.handleFrames([]frames.Frame{&frames.BlockedFrame{}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("errors on GOAWAY frames", func() {
		err := sess.handleFrames([]frames.Frame{&frames.GoawayFrame{}})
		Expect(err).To(MatchError("unimplemented: handling GOAWAY frames"))
	})

	It("handles STOP_WAITING frames", func() {
		err := sess.handleFrames([]frames.Frame{&frames.StopWaitingFrame{LeastUnacked: 10}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("handles CONNECTION_CLOSE frames", func() {
		str, _ := sess.GetOrOpenStream(5)
		err := sess.handleFrames([]frames.Frame{&frames.ConnectionCloseFrame{ErrorCode: 42, ReasonPhrase: "foobar"}})
		Expect(err).NotTo(HaveOccurred())
		_, err = str.Read([]byte{0})
		Expect(err).To(MatchError(qerr.Error(42, "foobar")))
	})

	Context("accepting streams", func() {
		It("waits for new streams", func() {
			var str Stream
			go func() {
				defer GinkgoRecover()
				var err error
				str, err = sess.AcceptStream()
				Expect(err).ToNot(HaveOccurred())
			}()
			Consistently(func() Stream { return str }).Should(BeNil())
			sess.handleStreamFrame(&frames.StreamFrame{
				StreamID: 3,
			})
			Eventually(func() Stream { return str }).ShouldNot(BeNil())
			Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
		})

		It("stops accepting when the session is closed", func() {
			testErr := errors.New("testErr")
			var err error
			go func() {
				_, err = sess.AcceptStream()
			}()
			go sess.run()
			Consistently(func() error { return err }).ShouldNot(HaveOccurred())
			sess.Close(testErr)
			Eventually(func() error { return err }).Should(HaveOccurred())
			Expect(err).To(MatchError(qerr.ToQuicError(testErr)))
		})

		It("stops accepting when the session is closed after version negotiation", func() {
			testErr := errCloseSessionForNewVersion
			var err error
			go func() {
				_, err = sess.AcceptStream()
			}()
			go sess.run()
			Consistently(func() error { return err }).ShouldNot(HaveOccurred())
			sess.Close(testErr)
			Eventually(func() error { return err }).Should(HaveOccurred())
			Expect(err).To(MatchError(testErr))
		})
	})

	Context("closing", func() {
		BeforeEach(func() {
			Eventually(areSessionsRunning).Should(BeFalse())
			go sess.run()
			Eventually(areSessionsRunning).Should(BeTrue())
		})

		It("shuts down without error", func() {
			sess.Close(nil)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written[0][len(mconn.written[0])-7:]).To(Equal([]byte{0x02, byte(qerr.PeerGoingAway), 0, 0, 0, 0, 0}))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(sess.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})

		It("only closes once", func() {
			sess.Close(nil)
			sess.Close(nil)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(sess.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := sess.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			sess.Close(testErr)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(closeCallbackCalled).To(BeTrue())
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			Expect(sess.runClosed).ToNot(Receive()) // channel should be drained by Close()
		})

		It("closes the session in order to replace it with another QUIC version", func() {
			sess.Close(errCloseSessionForNewVersion)
			Expect(closeCallbackCalled).To(BeFalse())
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(atomic.LoadUint32(&sess.closed) != 0).To(BeTrue())
			Expect(mconn.written).To(BeEmpty()) // no CONNECTION_CLOSE or PUBLIC_RESET sent
		})

		It("sends a Public Reset if the client is initiating the head-of-line blocking experiment", func() {
			sess.Close(handshake.ErrHOLExperiment)
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written[0][0] & 0x02).ToNot(BeZero()) // Public Reset
			Expect(sess.runClosed).ToNot(Receive())            // channel should be drained by Close()
		})
	})

	Context("receiving packets", func() {
		var hdr *PublicHeader

		BeforeEach(func() {
			sess.unpacker = &mockUnpacker{}
			clientSess.unpacker = &mockUnpacker{}
			hdr = &PublicHeader{PacketNumberLen: protocol.PacketNumberLen6}
		})

		It("sets the {last,largest}RcvdPacketNumber", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("sets the {last,largest}RcvdPacketNumber, for an out-of-order packet", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			hdr.PacketNumber = 3
			err = sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("ignores duplicate packets", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			err = sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		It("ignores packets smaller than the highest LeastUnacked of a StopWaiting", func() {
			err := sess.receivedPacketHandler.ReceivedStopWaiting(&frames.StopWaitingFrame{LeastUnacked: 10})
			Expect(err).ToNot(HaveOccurred())
			hdr.PacketNumber = 5
			err = sess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		It("passes the diversification nonce to the cryptoSetup, if it is a client", func() {
			hdr.PacketNumber = 5
			hdr.DiversificationNonce = []byte("foobar")
			err := clientSess.handlePacketImpl(&receivedPacket{publicHeader: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect((*[]byte)(unsafe.Pointer(reflect.ValueOf(clientSess.cryptoSetup).Elem().FieldByName("diversificationNonce").UnsafeAddr()))).To(Equal(&hdr.DiversificationNonce))
		})

		Context("updating the remote address", func() {
			It("sets the remote address", func() {
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				Expect(sess.conn.(*mockConnection).remoteAddr).ToNot(Equal(remoteIP))
				p := receivedPacket{
					remoteAddr:   remoteIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				err := sess.handlePacketImpl(&p)
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})

			It("doesn't change the remote address if authenticating the packet fails", func() {
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				attackerIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 102)}
				sess.conn.(*mockConnection).remoteAddr = remoteIP
				// use the real packetUnpacker here, to make sure this test fails if the error code for failed decryption changes
				sess.unpacker = &packetUnpacker{}
				sess.unpacker.(*packetUnpacker).aead = &mockAEAD{}
				p := receivedPacket{
					remoteAddr:   attackerIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				err := sess.handlePacketImpl(&p)
				quicErr := err.(*qerr.QuicError)
				Expect(quicErr.ErrorCode).To(Equal(qerr.DecryptionFailure))
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})

			It("sets the remote address, if the packet is authenticated, but unpacking fails for another reason", func() {
				testErr := errors.New("testErr")
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				Expect(sess.conn.(*mockConnection).remoteAddr).ToNot(Equal(remoteIP))
				p := receivedPacket{
					remoteAddr:   remoteIP,
					publicHeader: &PublicHeader{PacketNumber: 1337},
				}
				sess.unpacker.(*mockUnpacker).unpackErr = testErr
				err := sess.handlePacketImpl(&p)
				Expect(err).To(MatchError(testErr))
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})
		})
	})

	Context("sending packets", func() {
		It("sends ack frames", func() {
			packetNumber := protocol.PacketNumber(0x035E)
			sess.receivedPacketHandler.ReceivedPacket(packetNumber, true)
			err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written[0]).To(ContainSubstring(string([]byte{0x5E, 0x03})))
		})

		It("sends two WindowUpdate frames", func() {
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			sess.flowControlManager.AddBytesRead(5, protocol.ReceiveStreamFlowControlWindow)
			err = sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			err = sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			err = sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(2))
			Expect(mconn.written[0]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
			Expect(mconn.written[1]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
		})

		It("sends public reset", func() {
			err := sess.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		})

		It("informs the SentPacketHandler about sent packets", func() {
			sess.sentPacketHandler = newMockSentPacketHandler()
			sess.packer.packetNumberGenerator.next = 0x1337 + 9
			sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionSecure}

			f := &frames.StreamFrame{
				StreamID: 5,
				Data:     []byte("foobar"),
			}
			sess.streamFramer.AddFrameForRetransmission(f)
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			sentPackets := sess.sentPacketHandler.(*mockSentPacketHandler).sentPackets
			Expect(sentPackets).To(HaveLen(1))
			Expect(sentPackets[0].Frames).To(ContainElement(f))
			Expect(sentPackets[0].EncryptionLevel).To(Equal(protocol.EncryptionSecure))
			Expect(sentPackets[0].Length).To(BeEquivalentTo(len(mconn.written[0])))
		})
	})

	Context("retransmissions", func() {
		var sph *mockSentPacketHandler
		BeforeEach(func() {
			// a StopWaitingFrame is added, so make sure the packet number of the new package is higher than the packet number of the retransmitted packet
			sess.packer.packetNumberGenerator.next = 0x1337 + 10
			sph = newMockSentPacketHandler().(*mockSentPacketHandler)
			sess.sentPacketHandler = sph
			sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}
		})

		Context("for handshake packets", func() {
			It("retransmits an unencrypted packet", func() {
				sf := &frames.StreamFrame{StreamID: 1, Data: []byte("foobar")}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []frames.Frame{sf},
					EncryptionLevel: protocol.EncryptionUnencrypted,
				}}
				err := sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				sentPackets := sph.sentPackets
				Expect(sentPackets).To(HaveLen(1))
				Expect(sentPackets[0].EncryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
				Expect(sentPackets[0].Frames).To(HaveLen(2))
				Expect(sentPackets[0].Frames[1]).To(Equal(sf))
				swf := sentPackets[0].Frames[0].(*frames.StopWaitingFrame)
				Expect(swf.LeastUnacked).To(Equal(protocol.PacketNumber(0x1337)))
			})

			It("doesn't retransmit non-retransmittable packets", func() {
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames: []frames.Frame{
						&frames.AckFrame{},
						&frames.StopWaitingFrame{},
					},
					EncryptionLevel: protocol.EncryptionUnencrypted,
				}}
				err := sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(mconn.written).To(BeEmpty())
			})

			It("retransmit a packet encrypted with the initial encryption", func() {
				sf := &frames.StreamFrame{StreamID: 1, Data: []byte("foobar")}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []frames.Frame{sf},
					EncryptionLevel: protocol.EncryptionSecure,
				}}
				err := sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				sentPackets := sph.sentPackets
				Expect(sentPackets).To(HaveLen(1))
				Expect(sentPackets[0].EncryptionLevel).To(Equal(protocol.EncryptionSecure))
				Expect(sentPackets[0].Frames).To(HaveLen(2))
				Expect(sentPackets[0].Frames).To(ContainElement(sf))
			})
		})

		Context("for packets after the handshake", func() {
			BeforeEach(func() {
				sess.packer.SetForwardSecure()
			})

			It("sends a StreamFrame from a packet queued for retransmission", func() {
				f := frames.StreamFrame{
					StreamID: 0x5,
					Data:     []byte("foobar1234567"),
				}
				p := ackhandler.Packet{
					PacketNumber:    0x1337,
					Frames:          []frames.Frame{&f},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				sph.retransmissionQueue = []*ackhandler.Packet{&p}

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				Expect(sph.requestedStopWaiting).To(BeTrue())
				Expect(mconn.written[0]).To(ContainSubstring("foobar1234567"))
			})

			It("sends a StreamFrame from a packet queued for retransmission", func() {
				f1 := frames.StreamFrame{
					StreamID: 0x5,
					Data:     []byte("foobar"),
				}
				f2 := frames.StreamFrame{
					StreamID: 0x7,
					Data:     []byte("loremipsum"),
				}
				p1 := ackhandler.Packet{
					PacketNumber:    0x1337,
					Frames:          []frames.Frame{&f1},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				p2 := ackhandler.Packet{
					PacketNumber:    0x1338,
					Frames:          []frames.Frame{&f2},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				sph.retransmissionQueue = []*ackhandler.Packet{&p1, &p2}

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				Expect(mconn.written[0]).To(ContainSubstring("foobar"))
				Expect(mconn.written[0]).To(ContainSubstring("loremipsum"))
			})

			It("always attaches a StopWaiting to a packet that contains a retransmission", func() {
				f := &frames.StreamFrame{
					StreamID: 0x5,
					Data:     bytes.Repeat([]byte{'f'}, int(1.5*float32(protocol.MaxPacketSize))),
				}
				sess.streamFramer.AddFrameForRetransmission(f)

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(2))
				sentPackets := sph.sentPackets
				Expect(sentPackets).To(HaveLen(2))
				_, ok := sentPackets[0].Frames[0].(*frames.StopWaitingFrame)
				Expect(ok).To(BeTrue())
				_, ok = sentPackets[1].Frames[0].(*frames.StopWaitingFrame)
				Expect(ok).To(BeTrue())
			})

			It("retransmits a WindowUpdates if it hasn't already sent a WindowUpdate with a higher ByteOffset", func() {
				_, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				fc := newMockFlowControlHandler()
				fc.receiveWindow = 0x1000
				sess.flowControlManager = fc
				wuf := &frames.WindowUpdateFrame{
					StreamID:   5,
					ByteOffset: 0x1000,
				}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []frames.Frame{wuf},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}}
				err = sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(sph.sentPackets).To(HaveLen(1))
				Expect(sph.sentPackets[0].Frames).To(ContainElement(wuf))
			})

			It("doesn't retransmit WindowUpdates if it already sent a WindowUpdate with a higher ByteOffset", func() {
				_, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				fc := newMockFlowControlHandler()
				fc.receiveWindow = 0x2000
				sess.flowControlManager = fc
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames: []frames.Frame{&frames.WindowUpdateFrame{
						StreamID:   5,
						ByteOffset: 0x1000,
					}},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}}
				err = sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(sph.sentPackets).To(BeEmpty())
			})

			It("doesn't retransmit WindowUpdates for closed streams", func() {
				str, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				// close the stream
				str.(*stream).sentFin()
				str.Close()
				str.(*stream).RegisterRemoteError(nil)
				sess.garbageCollectStreams()
				_, err = sess.flowControlManager.SendWindowSize(5)
				Expect(err).To(MatchError("Error accessing the flowController map."))
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames: []frames.Frame{&frames.WindowUpdateFrame{
						StreamID:   5,
						ByteOffset: 0x1337,
					}},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}}
				err = sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(sph.sentPackets).To(BeEmpty())
			})
		})
	})

	It("retransmits RTO packets", func() {
		sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}
		// We simulate consistently low RTTs, so that the test works faster
		n := protocol.PacketNumber(10)
		for p := protocol.PacketNumber(1); p < n; p++ {
			err := sess.sentPacketHandler.SentPacket(&ackhandler.Packet{
				PacketNumber:    p,
				Length:          1,
				EncryptionLevel: protocol.EncryptionForwardSecure,
			})
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(time.Microsecond)
			ack := &frames.AckFrame{}
			ack.LargestAcked = p
			err = sess.sentPacketHandler.ReceivedAck(ack, p, time.Now())
			Expect(err).NotTo(HaveOccurred())
		}
		sess.packer.packetNumberGenerator.next = n + 1
		// Now, we send a single packet, and expect that it was retransmitted later
		err := sess.sentPacketHandler.SentPacket(&ackhandler.Packet{
			PacketNumber: n,
			Length:       1,
			Frames: []frames.Frame{&frames.StreamFrame{
				Data: []byte("foobar"),
			}},
			EncryptionLevel: protocol.EncryptionForwardSecure,
		})
		Expect(err).NotTo(HaveOccurred())
		go sess.run()
		defer sess.Close(nil)
		sess.scheduleSending()
		Eventually(func() [][]byte { return mconn.written }).ShouldNot(BeEmpty())
		Expect(mconn.written[0]).To(ContainSubstring("foobar"))
	})

	Context("scheduling sending", func() {
		BeforeEach(func() {
			sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}
		})

		It("sends after writing to a stream", func(done Done) {
			Expect(sess.sendingScheduled).NotTo(Receive())
			s, err := sess.GetOrOpenStream(3)
			Expect(err).NotTo(HaveOccurred())
			go func() {
				s.Write([]byte("foobar"))
				close(done)
			}()
			Eventually(sess.sendingScheduled).Should(Receive())
			s.(*stream).getDataForWriting(1000) // unblock
		})

		It("sets the timer to the ack timer", func() {
			rph := &mockReceivedPacketHandler{}
			rph.nextAckFrame = &frames.AckFrame{LargestAcked: 0x1337}
			sess.receivedPacketHandler = rph
			go sess.run()
			defer sess.Close(nil)
			sess.ackAlarmChanged(time.Now().Add(10 * time.Millisecond))
			time.Sleep(10 * time.Millisecond)
			Eventually(func() int { return len(mconn.written) }).ShouldNot(BeZero())
			Expect(mconn.written[0]).To(ContainSubstring(string([]byte{0x37, 0x13})))
		})

		Context("bundling of small packets", func() {
			It("bundles two small frames of different streams into one packet", func() {
				s1, err := sess.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				s2, err := sess.GetOrOpenStream(7)
				Expect(err).NotTo(HaveOccurred())

				// Put data directly into the streams
				s1.(*stream).dataForWriting = []byte("foobar1")
				s2.(*stream).dataForWriting = []byte("foobar2")

				sess.scheduleSending()
				go sess.run()
				defer sess.Close(nil)

				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(1))
				Expect(mconn.written[0]).To(ContainSubstring("foobar1"))
				Expect(mconn.written[0]).To(ContainSubstring("foobar2"))
			})

			It("sends out two big frames in two packets", func() {
				s1, err := sess.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				s2, err := sess.GetOrOpenStream(7)
				Expect(err).NotTo(HaveOccurred())
				go sess.run()
				defer sess.Close(nil)
				go func() {
					defer GinkgoRecover()
					s1.Write(bytes.Repeat([]byte{'e'}, 1000))
				}()
				_, err = s2.Write(bytes.Repeat([]byte{'e'}, 1000))
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(2))
			})

			It("sends out two small frames that are written to long after one another into two packets", func() {
				s, err := sess.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				go sess.run()
				defer sess.Close(nil)
				_, err = s.Write([]byte("foobar1"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(2))
			})

			It("sends a queued ACK frame only once", func() {
				packetNumber := protocol.PacketNumber(0x1337)
				sess.receivedPacketHandler.ReceivedPacket(packetNumber, true)

				s, err := sess.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				go sess.run()
				defer sess.Close(nil)
				_, err = s.Write([]byte("foobar1"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(2))
				Expect(mconn.written[0]).To(ContainSubstring(string([]byte{0x37, 0x13})))
				Expect(mconn.written[1]).ToNot(ContainSubstring(string([]byte{0x37, 0x13})))
			})
		})
	})

	It("tells the packetPacker when forward-secure encryption is used", func() {
		go sess.run()
		defer sess.Close(nil)
		sess.aeadChanged <- protocol.EncryptionSecure
		Consistently(func() bool { return sess.packer.isForwardSecure }).Should(BeFalse())
		sess.aeadChanged <- protocol.EncryptionForwardSecure
		Eventually(func() bool { return sess.packer.isForwardSecure }).Should(BeTrue())
	})

	It("closes when crypto stream errors", func() {
		go sess.run()
		s, err := sess.GetOrOpenStream(3)
		Expect(err).NotTo(HaveOccurred())
		err = sess.handleStreamFrame(&frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("4242\x00\x00\x00\x00"),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool { return atomic.LoadUint32(&sess.closed) != 0 }).Should(BeTrue())
		_, err = s.Write([]byte{})
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidCryptoMessageType))
	})

	Context("sending a Public Reset when receiving undecryptable packets during the handshake", func() {
		// sends protocol.MaxUndecryptablePackets+1 undecrytable packets
		// this completely fills up the undecryptable packets queue and triggers the public reset timer
		sendUndecryptablePackets := func() {
			for i := 0; i < protocol.MaxUndecryptablePackets+1; i++ {
				hdr := &PublicHeader{
					PacketNumber: protocol.PacketNumber(i + 1),
				}
				sess.handlePacket(&receivedPacket{publicHeader: hdr, data: []byte("foobar")})
			}
		}

		BeforeEach(func() {
			sess.unpacker = &mockUnpacker{unpackErr: qerr.Error(qerr.DecryptionFailure, "")}
			sess.cryptoSetup = &mockCryptoSetup{}
		})

		It("doesn't immediately send a Public Reset after receiving too many undecryptable packets", func() {
			go sess.run()
			sendUndecryptablePackets()
			sess.scheduleSending()
			Consistently(func() [][]byte { return mconn.written }).Should(HaveLen(0))
		})

		It("sets a deadline to send a Public Reset after receiving too many undecryptable packets", func() {
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() time.Time { return sess.receivedTooManyUndecrytablePacketsTime }).Should(BeTemporally("~", time.Now(), 10*time.Millisecond))
			sess.Close(nil)
		})

		It("drops undecryptable packets when the undecrytable packet queue is full", func() {
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() []*receivedPacket { return sess.undecryptablePackets }).Should(HaveLen(protocol.MaxUndecryptablePackets))
			// check that old packets are kept, and the new packets are dropped
			Expect(sess.undecryptablePackets[0].publicHeader.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			sess.Close(nil)
		})

		It("sends a Public Reset after a timeout", func() {
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() time.Time { return sess.receivedTooManyUndecrytablePacketsTime }).Should(BeTemporally("~", time.Now(), time.Millisecond))
			// speed up this test by manually setting back the time when too many packets were received
			sess.receivedTooManyUndecrytablePacketsTime = time.Now().Add(-protocol.PublicResetTimeout)
			time.Sleep(10 * time.Millisecond) // wait for the run loop to spin up
			sess.scheduleSending()            // wake up the run loop
			Eventually(func() [][]byte { return mconn.written }).Should(HaveLen(1))
			Expect(mconn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
			Expect(sess.runClosed).To(Receive())
		})

		It("doesn't send a Public Reset if decrypting them suceeded during the timeout", func() {
			go sess.run()
			sess.receivedTooManyUndecrytablePacketsTime = time.Now().Add(-protocol.PublicResetTimeout).Add(-time.Millisecond)
			sess.scheduleSending() // wake up the run loop
			// there are no packets in the undecryptable packet queue
			// in reality, this happens when the trial decryption succeeded during the Public Reset timeout
			Consistently(func() [][]byte { return mconn.written }).ShouldNot(HaveLen(1))
			Expect(sess.runClosed).ToNot(Receive())
			sess.Close(nil)
		})

		It("ignores undecryptable packets after the handshake is complete", func() {
			sess.cryptoSetup.(*mockCryptoSetup).handshakeComplete = true
			go sess.run()
			sendUndecryptablePackets()
			Consistently(sess.undecryptablePackets).Should(BeEmpty())
			sess.closeImpl(nil, true)
			Eventually(sess.runClosed).Should(Receive())
		})

		It("unqueues undecryptable packets for later decryption", func() {
			sess.undecryptablePackets = []*receivedPacket{{
				publicHeader: &PublicHeader{PacketNumber: protocol.PacketNumber(42)},
			}}
			Expect(sess.receivedPackets).NotTo(Receive())
			sess.tryDecryptingQueuedPackets()
			Expect(sess.undecryptablePackets).To(BeEmpty())
			Expect(sess.receivedPackets).To(Receive())
		})
	})

	It("calls the cryptoChangeCallback when the AEAD changes", func(done Done) {
		var callbackCalled bool
		var callbackCalledWith bool
		var callbackSession Session
		cb := func(s Session, p bool) {
			callbackCalled = true
			callbackCalledWith = p
			callbackSession = s
		}
		sess.cryptoChangeCallback = cb
		sess.aeadChanged <- protocol.EncryptionSecure
		go sess.run()
		defer sess.Close(nil)
		Eventually(func() bool { return callbackCalled }).Should(BeTrue())
		Expect(callbackCalledWith).To(BeFalse())
		Expect(callbackSession).To(Equal(sess))
		close(done)
	})

	It("calls the cryptoChangeCallback when the AEAD changes to forward secure encryption", func(done Done) {
		var callbackCalledWith bool
		var callbackSession Session
		cb := func(s Session, p bool) {
			callbackSession = s
			callbackCalledWith = p
		}
		sess.cryptoChangeCallback = cb
		sess.cryptoSetup = &mockCryptoSetup{handshakeComplete: true}
		sess.aeadChanged <- protocol.EncryptionForwardSecure
		go sess.run()
		defer sess.Close(nil)
		Eventually(func() bool { return callbackCalledWith }).Should(BeTrue())
		Expect(callbackSession).To(Equal(sess))
		close(done)
	})

	Context("timeouts", func() {
		It("times out due to no network activity", func(done Done) {
			sess.lastNetworkActivityTime = time.Now().Add(-time.Hour)
			sess.run() // Would normally not return
			Expect(mconn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(sess.runClosed).To(Receive())
			close(done)
		})

		It("times out due to non-completed crypto handshake", func(done Done) {
			sess.sessionCreationTime = time.Now().Add(-time.Hour)
			sess.run() // Would normally not return
			Expect(mconn.written[0]).To(ContainSubstring("Crypto handshake did not complete in time."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(sess.runClosed).To(Receive())
			close(done)
		})

		It("does not use ICSL before handshake", func(done Done) {
			sess.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			cpm.idleTime = 99999 * time.Second
			sess.packer.connectionParameters = sess.connectionParameters
			sess.run() // Would normally not return
			Expect(mconn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(sess.runClosed).To(Receive())
			close(done)
		})

		It("uses ICSL after handshake", func(done Done) {
			// sess.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			*(*bool)(unsafe.Pointer(reflect.ValueOf(sess.cryptoSetup).Elem().FieldByName("receivedForwardSecurePacket").UnsafeAddr())) = true
			*(*crypto.AEAD)(unsafe.Pointer(reflect.ValueOf(sess.cryptoSetup).Elem().FieldByName("forwardSecureAEAD").UnsafeAddr())) = &crypto.NullAEAD{}
			cpm.idleTime = 0 * time.Millisecond
			sess.packer.connectionParameters = sess.connectionParameters
			sess.run() // Would normally not return
			Expect(mconn.written[0]).To(ContainSubstring("No recent network activity."))
			Expect(closeCallbackCalled).To(BeTrue())
			Expect(sess.runClosed).To(Receive())
			close(done)
		})
	})

	It("stores up to MaxSessionUnprocessedPackets packets", func(done Done) {
		// Nothing here should block
		for i := protocol.PacketNumber(0); i < protocol.MaxSessionUnprocessedPackets+10; i++ {
			sess.handlePacket(&receivedPacket{})
		}
		close(done)
	}, 0.5)

	Context("getting streams", func() {
		It("returns a new stream", func() {
			str, err := sess.GetOrOpenStream(11)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
			Expect(str.StreamID()).To(Equal(protocol.StreamID(11)))
		})

		It("returns a nil-value (not an interface with value nil) for closed streams", func() {
			_, err := sess.GetOrOpenStream(9)
			Expect(err).ToNot(HaveOccurred())
			sess.streamsMap.RemoveStream(9)
			sess.garbageCollectStreams()
			Expect(sess.streamsMap.GetOrOpenStream(9)).To(BeNil())
			str, err := sess.GetOrOpenStream(9)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(BeNil())
			// make sure that the returned value is a plain nil, not an Stream with value nil
			_, ok := str.(Stream)
			Expect(ok).To(BeFalse())
		})

		// all relevant tests for this are in the streamsMap
		It("opens streams synchronously", func() {
			str, err := sess.OpenStreamSync()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
		})
	})

	Context("counting streams", func() {
		It("errors when too many streams are opened", func() {
			for i := 0; i < 110; i++ {
				_, err := sess.GetOrOpenStream(protocol.StreamID(i*2 + 1))
				Expect(err).NotTo(HaveOccurred())
			}
			_, err := sess.GetOrOpenStream(protocol.StreamID(301))
			Expect(err).To(MatchError(qerr.TooManyOpenStreams))
		})

		It("does not error when many streams are opened and closed", func() {
			for i := 2; i <= 1000; i++ {
				s, err := sess.GetOrOpenStream(protocol.StreamID(i*2 + 1))
				Expect(err).NotTo(HaveOccurred())
				err = s.Close()
				Expect(err).NotTo(HaveOccurred())
				s.(*stream).sentFin()
				s.(*stream).CloseRemote(0)
				_, err = s.Read([]byte("a"))
				Expect(err).To(MatchError(io.EOF))
				sess.garbageCollectStreams()
			}
		})
	})

	Context("ignoring errors", func() {
		It("ignores duplicate acks", func() {
			sess.sentPacketHandler.SentPacket(&ackhandler.Packet{
				PacketNumber: 1,
				Length:       1,
			})
			err := sess.handleFrames([]frames.Frame{&frames.AckFrame{
				LargestAcked: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
			err = sess.handleFrames([]frames.Frame{&frames.AckFrame{
				LargestAcked: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("window updates", func() {
		It("gets stream level window updates", func() {
			err := sess.flowControlManager.AddBytesRead(1, protocol.ReceiveStreamFlowControlWindow)
			Expect(err).NotTo(HaveOccurred())
			frames, err := sess.getWindowUpdateFrames()
			Expect(err).NotTo(HaveOccurred())
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].StreamID).To(Equal(protocol.StreamID(1)))
			Expect(frames[0].ByteOffset).To(Equal(protocol.ReceiveStreamFlowControlWindow * 2))
		})

		It("gets connection level window updates", func() {
			_, err := sess.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			err = sess.flowControlManager.AddBytesRead(5, protocol.ReceiveConnectionFlowControlWindow)
			Expect(err).NotTo(HaveOccurred())
			frames, err := sess.getWindowUpdateFrames()
			Expect(err).NotTo(HaveOccurred())
			Expect(frames).To(HaveLen(1))
			Expect(frames[0].StreamID).To(Equal(protocol.StreamID(0)))
			Expect(frames[0].ByteOffset).To(Equal(protocol.ReceiveConnectionFlowControlWindow * 2))
		})
	})

	It("returns the local address", func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
		mconn.localAddr = addr
		Expect(sess.LocalAddr()).To(Equal(addr))
	})

	It("returns the remote address", func() {
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 7, 1), Port: 7331}
		mconn.remoteAddr = addr
		Expect(sess.RemoteAddr()).To(Equal(addr))
	})
})
