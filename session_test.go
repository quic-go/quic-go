package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type mockConnection struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	written    chan []byte
}

func newMockConnection() *mockConnection {
	return &mockConnection{
		remoteAddr: &net.UDPAddr{},
		written:    make(chan []byte, 100),
	}
}

func (m *mockConnection) Write(p []byte) error {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case m.written <- b:
	default:
		panic("mockConnection channel full")
	}
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

func (m *mockUnpacker) Unpack(headerBinary []byte, hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	if m.unpackErr != nil {
		return nil, m.unpackErr
	}
	return &unpackedPacket{
		frames: nil,
	}, nil
}

type mockSentPacketHandler struct {
	retransmissionQueue             []*ackhandler.Packet
	sentPackets                     []*ackhandler.Packet
	congestionLimited               bool
	requestedStopWaiting            bool
	shouldSendRetransmittablePacket bool
}

func (h *mockSentPacketHandler) SentPacket(packet *ackhandler.Packet) error {
	h.sentPackets = append(h.sentPackets, packet)
	return nil
}

func (h *mockSentPacketHandler) ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, recvTime time.Time) error {
	return nil
}
func (h *mockSentPacketHandler) SetHandshakeComplete()                  {}
func (h *mockSentPacketHandler) GetLeastUnacked() protocol.PacketNumber { return 1 }
func (h *mockSentPacketHandler) GetAlarmTimeout() time.Time             { panic("not implemented") }
func (h *mockSentPacketHandler) OnAlarm()                               { panic("not implemented") }
func (h *mockSentPacketHandler) SendingAllowed() bool                   { return !h.congestionLimited }
func (h *mockSentPacketHandler) ShouldSendRetransmittablePacket() bool {
	b := h.shouldSendRetransmittablePacket
	h.shouldSendRetransmittablePacket = false
	return b
}

func (h *mockSentPacketHandler) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	h.requestedStopWaiting = true
	return &wire.StopWaitingFrame{LeastUnacked: 0x1337}
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
	nextAckFrame *wire.AckFrame
	ackAlarm     time.Time
}

func (m *mockReceivedPacketHandler) GetAckFrame() *wire.AckFrame {
	f := m.nextAckFrame
	m.nextAckFrame = nil
	return f
}
func (m *mockReceivedPacketHandler) ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error {
	panic("not implemented")
}
func (m *mockReceivedPacketHandler) IgnoreBelow(protocol.PacketNumber) {
	panic("not implemented")
}
func (m *mockReceivedPacketHandler) GetAlarmTimeout() time.Time { return m.ackAlarm }

var _ ackhandler.ReceivedPacketHandler = &mockReceivedPacketHandler{}

func areSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*session).run")
}

var _ = Describe("Session", func() {
	var (
		sess        *session
		scfg        *handshake.ServerConfig
		mconn       *mockConnection
		cryptoSetup *mockCryptoSetup
		aeadChanged chan<- protocol.EncryptionLevel
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		cryptoSetup = &mockCryptoSetup{}
		newCryptoSetup = func(
			_ io.ReadWriter,
			_ protocol.ConnectionID,
			_ net.Addr,
			_ protocol.VersionNumber,
			_ *handshake.ServerConfig,
			_ *handshake.TransportParameters,
			_ []protocol.VersionNumber,
			_ func(net.Addr, *Cookie) bool,
			_ chan<- handshake.TransportParameters,
			aeadChangedP chan<- protocol.EncryptionLevel,
		) (handshake.CryptoSetup, error) {
			aeadChanged = aeadChangedP
			return cryptoSetup, nil
		}

		mconn = newMockConnection()
		certChain := crypto.NewCertChain(testdata.GetTLSConfig())
		kex, err := crypto.NewCurve25519KEX()
		Expect(err).NotTo(HaveOccurred())
		scfg, err = handshake.NewServerConfig(kex, certChain)
		Expect(err).NotTo(HaveOccurred())
		var pSess Session
		pSess, err = newSession(
			mconn,
			protocol.Version39,
			0,
			scfg,
			nil,
			populateServerConfig(&Config{}),
		)
		Expect(err).NotTo(HaveOccurred())
		sess = pSess.(*session)
		Expect(sess.streamsMap.openStreams).To(BeEmpty())
	})

	AfterEach(func() {
		newCryptoSetup = handshake.NewCryptoSetup
		Eventually(areSessionsRunning).Should(BeFalse())
	})

	Context("source address validation", func() {
		var (
			cookieVerify    func(net.Addr, *Cookie) bool
			paramClientAddr net.Addr
			paramCookie     *Cookie
		)
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1000}

		BeforeEach(func() {
			newCryptoSetup = func(
				_ io.ReadWriter,
				_ protocol.ConnectionID,
				_ net.Addr,
				_ protocol.VersionNumber,
				_ *handshake.ServerConfig,
				_ *handshake.TransportParameters,
				_ []protocol.VersionNumber,
				cookieFunc func(net.Addr, *Cookie) bool,
				_ chan<- handshake.TransportParameters,
				_ chan<- protocol.EncryptionLevel,
			) (handshake.CryptoSetup, error) {
				cookieVerify = cookieFunc
				return cryptoSetup, nil
			}

			conf := populateServerConfig(&Config{})
			conf.AcceptCookie = func(clientAddr net.Addr, cookie *Cookie) bool {
				paramClientAddr = clientAddr
				paramCookie = cookie
				return false
			}
			pSess, err := newSession(
				mconn,
				protocol.Version39,
				0,
				scfg,
				nil,
				conf,
			)
			Expect(err).NotTo(HaveOccurred())
			sess = pSess.(*session)
		})

		It("calls the callback with the right parameters when the client didn't send an STK", func() {
			cookieVerify(remoteAddr, nil)
			Expect(paramClientAddr).To(Equal(remoteAddr))
			Expect(paramCookie).To(BeNil())
		})

		It("calls the callback with the STK when the client sent an STK", func() {
			cookieAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			sentTime := time.Now().Add(-time.Hour)
			cookieVerify(remoteAddr, &Cookie{SentTime: sentTime, RemoteAddr: cookieAddr.String()})
			Expect(paramClientAddr).To(Equal(remoteAddr))
			Expect(paramCookie).ToNot(BeNil())
			Expect(paramCookie.RemoteAddr).To(Equal(cookieAddr.String()))
			Expect(paramCookie.SentTime).To(Equal(sentTime))
		})
	})

	Context("frame handling", func() {
		BeforeEach(func() {
			sess.streamsMap.newStream = func(id protocol.StreamID) streamI {
				str := mocks.NewMockStreamI(mockCtrl)
				str.EXPECT().StreamID().Return(id).AnyTimes()
				if id == 1 {
					str.EXPECT().Finished().AnyTimes()
				}
				return str
			}
		})

		Context("handling STREAM frames", func() {
			BeforeEach(func() {
				sess.streamsMap.UpdateMaxStreamLimit(100)
			})

			It("makes new streams", func() {
				f := &wire.StreamFrame{
					StreamID: 5,
					Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				}
				newStreamLambda := sess.streamsMap.newStream
				sess.streamsMap.newStream = func(id protocol.StreamID) streamI {
					str := newStreamLambda(id)
					if id == 5 {
						str.(*mocks.MockStreamI).EXPECT().AddStreamFrame(f)
					}
					return str
				}
				err := sess.handleStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.streamsMap.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(str).ToNot(BeNil())
			})

			It("handles existing streams", func() {
				f1 := &wire.StreamFrame{
					StreamID: 5,
					Data:     []byte{0xde, 0xca},
				}
				f2 := &wire.StreamFrame{
					StreamID: 5,
					Offset:   2,
					Data:     []byte{0xfb, 0xad},
				}
				newStreamLambda := sess.streamsMap.newStream
				sess.streamsMap.newStream = func(id protocol.StreamID) streamI {
					str := newStreamLambda(id)
					if id == 5 {
						str.(*mocks.MockStreamI).EXPECT().AddStreamFrame(f1)
						str.(*mocks.MockStreamI).EXPECT().AddStreamFrame(f2)
					}
					return str
				}
				sess.handleStreamFrame(f1)
				numOpenStreams := len(sess.streamsMap.openStreams)
				sess.handleStreamFrame(f2)
				Expect(sess.streamsMap.openStreams).To(HaveLen(numOpenStreams))
			})

			It("ignores STREAM frames for closed streams", func() {
				sess.streamsMap.streams[5] = nil
				str, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				Expect(str).To(BeNil()) // make sure the stream is gone
				err = sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar"),
				})
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors on a STREAM frame that would close the crypto stream", func() {
				err := sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: sess.version.CryptoStreamID(),
					Offset:   0x1337,
					FinBit:   true,
				})
				Expect(err).To(MatchError("Received STREAM frame with FIN bit for the crypto stream"))
			})
		})

		Context("handling RST_STREAM frames", func() {
			It("closes the streams for writing", func() {
				str, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				str.(*mocks.MockStreamI).EXPECT().RegisterRemoteError(
					errors.New("RST_STREAM received with code 42"),
					protocol.ByteCount(0x1337),
				)
				err = sess.handleRstStreamFrame(&wire.RstStreamFrame{
					StreamID:   5,
					ErrorCode:  42,
					ByteOffset: 0x1337,
				})
				Expect(err).ToNot(HaveOccurred())
			})

			It("queues a RST_STERAM frame", func() {
				sess.queueResetStreamFrame(5, 0x1337)
				Expect(sess.packer.controlFrames).To(HaveLen(1))
				Expect(sess.packer.controlFrames[0].(*wire.RstStreamFrame)).To(Equal(&wire.RstStreamFrame{
					StreamID:   5,
					ByteOffset: 0x1337,
				}))
			})

			It("returns errors", func() {
				testErr := errors.New("flow control violation")
				str, err := sess.GetOrOpenStream(5)
				Expect(err).ToNot(HaveOccurred())
				str.(*mocks.MockStreamI).EXPECT().RegisterRemoteError(gomock.Any(), gomock.Any()).Return(testErr)
				err = sess.handleRstStreamFrame(&wire.RstStreamFrame{
					StreamID:   5,
					ByteOffset: 0x1337,
				})
				Expect(err).To(MatchError(testErr))
			})

			It("ignores the error when the stream is not known", func() {
				str, err := sess.GetOrOpenStream(3)
				Expect(err).ToNot(HaveOccurred())
				str.(*mocks.MockStreamI).EXPECT().Finished().Return(true)
				sess.streamsMap.DeleteClosedStreams()
				str, err = sess.GetOrOpenStream(3)
				Expect(err).ToNot(HaveOccurred())
				Expect(str).To(BeNil())
				err = sess.handleFrames([]wire.Frame{&wire.RstStreamFrame{
					StreamID:  3,
					ErrorCode: 42,
				}}, protocol.EncryptionUnspecified)
				Expect(err).NotTo(HaveOccurred())
			})

			It("erros when a RST_STREAM frame would reset the crypto stream", func() {
				err := sess.handleRstStreamFrame(&wire.RstStreamFrame{
					StreamID:  sess.version.CryptoStreamID(),
					ErrorCode: 123,
				})
				Expect(err).To(MatchError("Received RST_STREAM frame for the crypto stream"))
			})
		})

		Context("handling MAX_DATA and MAX_STREAM_DATA frames", func() {
			var connFC *mocks.MockConnectionFlowController

			BeforeEach(func() {
				connFC = mocks.NewMockConnectionFlowController(mockCtrl)
				sess.connFlowController = connFC
			})

			It("updates the flow control window of the crypto stream", func() {
				fc := mocks.NewMockStreamFlowController(mockCtrl)
				offset := protocol.ByteCount(0x4321)
				fc.EXPECT().UpdateSendWindow(offset)
				sess.cryptoStream.(*cryptoStream).flowController = fc
				err := sess.handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
					StreamID:   sess.version.CryptoStreamID(),
					ByteOffset: offset,
				})
				Expect(err).ToNot(HaveOccurred())
			})

			It("updates the flow control window of a stream", func() {
				offset := protocol.ByteCount(0x1234)
				str, err := sess.GetOrOpenStream(5)
				str.(*mocks.MockStreamI).EXPECT().UpdateSendWindow(offset)
				Expect(err).ToNot(HaveOccurred())
				err = sess.handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
					StreamID:   5,
					ByteOffset: offset,
				})
				Expect(err).ToNot(HaveOccurred())
			})

			It("updates the flow control window of the connection", func() {
				offset := protocol.ByteCount(0x800000)
				connFC.EXPECT().UpdateSendWindow(offset)
				sess.handleMaxDataFrame(&wire.MaxDataFrame{ByteOffset: offset})
			})

			It("opens a new stream when receiving a MAX_STREAM_DATA frame for an unknown stream", func() {
				newStreamLambda := sess.streamsMap.newStream
				sess.streamsMap.newStream = func(id protocol.StreamID) streamI {
					str := newStreamLambda(id)
					if id == 5 {
						str.(*mocks.MockStreamI).EXPECT().UpdateSendWindow(protocol.ByteCount(0x1337))
					}
					return str
				}
				err := sess.handleMaxStreamDataFrame(&wire.MaxStreamDataFrame{
					StreamID:   5,
					ByteOffset: 0x1337,
				})
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.streamsMap.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				Expect(str).ToNot(BeNil())
			})

			It("ignores MAX_STREAM_DATA frames for a closed stream", func() {
				str, err := sess.GetOrOpenStream(3)
				Expect(err).ToNot(HaveOccurred())
				str.(*mocks.MockStreamI).EXPECT().Finished().Return(true)
				err = sess.streamsMap.DeleteClosedStreams()
				Expect(err).ToNot(HaveOccurred())
				str, err = sess.GetOrOpenStream(3)
				Expect(err).ToNot(HaveOccurred())
				Expect(str).To(BeNil())
				err = sess.handleFrames([]wire.Frame{&wire.MaxStreamDataFrame{
					StreamID:   3,
					ByteOffset: 1337,
				}}, protocol.EncryptionUnspecified)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		It("handles PING frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.PingFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles BLOCKED frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.BlockedFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("errors on GOAWAY frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.GoawayFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).To(MatchError("unimplemented: handling GOAWAY frames"))
		})

		It("handles STOP_WAITING frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.StopWaitingFrame{LeastUnacked: 10}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles CONNECTION_CLOSE frames", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err).To(MatchError("ProofInvalid: foobar"))
				close(done)
			}()
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			sess.streamsMap.Range(func(s streamI) {
				s.(*mocks.MockStreamI).EXPECT().Cancel(gomock.Any())
			})
			err = sess.handleFrames([]wire.Frame{&wire.ConnectionCloseFrame{ErrorCode: qerr.ProofInvalid, ReasonPhrase: "foobar"}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess.Context().Done()).Should(BeClosed())
			Eventually(done).Should(BeClosed())
		})
	})

	It("tells its versions", func() {
		sess.version = 4242
		Expect(sess.GetVersion()).To(Equal(protocol.VersionNumber(4242)))
	})

	Context("waiting until the handshake completes", func() {
		It("waits until the handshake is complete", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := sess.WaitUntilHandshakeComplete()
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()
			aeadChanged <- protocol.EncryptionForwardSecure
			Consistently(done).ShouldNot(BeClosed())
			close(aeadChanged)
			Eventually(done).Should(BeClosed())
			Expect(sess.Close(nil)).To(Succeed())
		})

		It("errors if the handshake fails", func(done Done) {
			testErr := errors.New("crypto error")
			sess.cryptoSetup = &mockCryptoSetup{handleErr: testErr}
			go sess.run()
			err := sess.WaitUntilHandshakeComplete()
			Expect(err).To(MatchError(testErr))
			close(done)
		}, 0.5)

		It("returns when Close is called", func(done Done) {
			testErr := errors.New("close error")
			go sess.run()
			var waitReturned bool
			go func() {
				defer GinkgoRecover()
				err := sess.WaitUntilHandshakeComplete()
				Expect(err).To(MatchError(testErr))
				waitReturned = true
			}()
			sess.Close(testErr)
			Eventually(func() bool { return waitReturned }).Should(BeTrue())
			close(done)
		})

		It("doesn't wait if the handshake is already completed", func(done Done) {
			go sess.run()
			close(aeadChanged)
			err := sess.WaitUntilHandshakeComplete()
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.Close(nil)).To(Succeed())
			close(done)
		})
	})

	Context("accepting streams", func() {
		BeforeEach(func() {
			// don't use the mock here
			sess.streamsMap.newStream = sess.newStream
		})

		It("waits for new streams", func() {
			strChan := make(chan Stream)
			// accept two streams
			go func() {
				defer GinkgoRecover()
				for i := 0; i < 2; i++ {
					str, err := sess.AcceptStream()
					Expect(err).ToNot(HaveOccurred())
					strChan <- str
				}
			}()
			Consistently(strChan).ShouldNot(Receive())
			// this could happen e.g. by receiving a STREAM frame
			_, err := sess.GetOrOpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			var str Stream
			Eventually(strChan).Should(Receive(&str))
			Expect(str.StreamID()).To(Equal(protocol.StreamID(3)))
			Eventually(strChan).Should(Receive(&str))
			Expect(str.StreamID()).To(Equal(protocol.StreamID(5)))
		})

		It("stops accepting when the session is closed", func() {
			testErr := errors.New("testErr")
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := sess.AcceptStream()
				Expect(err).To(MatchError(qerr.ToQuicError(testErr)))
				close(done)
			}()
			go sess.run()
			Consistently(done).ShouldNot(BeClosed())
			sess.Close(testErr)
			Eventually(done).Should(BeClosed())
		})

		It("stops accepting when the session is closed after version negotiation", func() {
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := sess.AcceptStream()
				Expect(err).To(MatchError(qerr.Error(qerr.InternalError, errCloseSessionForNewVersion.Error())))
				close(done)
			}()
			go sess.run()
			Consistently(done).ShouldNot(BeClosed())
			Expect(sess.Context().Done()).ToNot(BeClosed())
			sess.Close(errCloseSessionForNewVersion)
			Eventually(done).Should(BeClosed())
			Eventually(sess.Context().Done()).Should(BeClosed())
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
			buf := &bytes.Buffer{}
			err := (&wire.ConnectionCloseFrame{ErrorCode: qerr.PeerGoingAway}).Write(buf, sess.version)
			Expect(err).ToNot(HaveOccurred())
			Expect(mconn.written).To(Receive(ContainSubstring(string(buf.Bytes()))))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("only closes once", func() {
			sess.Close(nil)
			sess.Close(nil)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := sess.GetOrOpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			sess.Close(testErr)
			Eventually(areSessionsRunning).Should(BeFalse())
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err.Error()).To(ContainSubstring(testErr.Error()))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes the session in order to replace it with another QUIC version", func() {
			sess.Close(errCloseSessionForNewVersion)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(BeEmpty()) // no CONNECTION_CLOSE or PUBLIC_RESET sent
		})

		It("sends a Public Reset if the client is initiating the head-of-line blocking experiment", func() {
			sess.Close(handshake.ErrHOLExperiment)
			Expect(mconn.written).To(HaveLen(1))
			Expect((<-mconn.written)[0] & 0x02).ToNot(BeZero()) // Public Reset
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("sends a Public Reset if the client is initiating the no STOP_WAITING experiment", func() {
			sess.Close(handshake.ErrHOLExperiment)
			Expect(mconn.written).To(HaveLen(1))
			Expect((<-mconn.written)[0] & 0x02).ToNot(BeZero()) // Public Reset
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("cancels the context when the run loop exists", func() {
			returned := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ctx := sess.Context()
				<-ctx.Done()
				Expect(ctx.Err()).To(MatchError(context.Canceled))
				close(returned)
			}()
			Consistently(returned).ShouldNot(BeClosed())
			sess.Close(nil)
			Eventually(returned).Should(BeClosed())
		})
	})

	Context("receiving packets", func() {
		var hdr *wire.Header

		BeforeEach(func() {
			sess.unpacker = &mockUnpacker{}
			hdr = &wire.Header{PacketNumberLen: protocol.PacketNumberLen6}
		})

		It("sets the {last,largest}RcvdPacketNumber", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("closes when handling a packet fails", func(done Done) {
			testErr := errors.New("unpack error")
			hdr.PacketNumber = 5
			var runErr error
			go func() {
				runErr = sess.run()
			}()
			sess.unpacker.(*mockUnpacker).unpackErr = testErr
			sess.handlePacket(&receivedPacket{header: hdr})
			Eventually(func() error { return runErr }).Should(MatchError(testErr))
			Expect(sess.Context().Done()).To(BeClosed())
			close(done)
		})

		It("sets the {last,largest}RcvdPacketNumber, for an out-of-order packet", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			hdr.PacketNumber = 3
			err = sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(3)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("handles duplicate packets", func() {
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			err = sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		Context("updating the remote address", func() {
			It("doesn't support connection migration", func() {
				origAddr := sess.conn.(*mockConnection).remoteAddr
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				Expect(origAddr).ToNot(Equal(remoteIP))
				p := receivedPacket{
					remoteAddr: remoteIP,
					header:     &wire.Header{PacketNumber: 1337},
				}
				err := sess.handlePacketImpl(&p)
				Expect(err).ToNot(HaveOccurred())
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(origAddr))
			})

			It("doesn't change the remote address if authenticating the packet fails", func() {
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				attackerIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 102)}
				sess.conn.(*mockConnection).remoteAddr = remoteIP
				// use the real packetUnpacker here, to make sure this test fails if the error code for failed decryption changes
				sess.unpacker = &packetUnpacker{}
				sess.unpacker.(*packetUnpacker).aead = &mockAEAD{}
				p := receivedPacket{
					remoteAddr: attackerIP,
					header:     &wire.Header{PacketNumber: 1337},
				}
				err := sess.handlePacketImpl(&p)
				quicErr := err.(*qerr.QuicError)
				Expect(quicErr.ErrorCode).To(Equal(qerr.DecryptionFailure))
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(remoteIP))
			})
		})
	})

	Context("sending packets", func() {
		BeforeEach(func() {
			sess.packer.hasSentPacket = true // make sure this is not the first packet the packer sends
		})

		It("sends ACK frames", func() {
			packetNumber := protocol.PacketNumber(0x035e)
			err := sess.receivedPacketHandler.ReceivedPacket(packetNumber, true)
			Expect(err).ToNot(HaveOccurred())
			err = sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring(string([]byte{0x03, 0x5e}))))
		})

		It("sends ACK frames when congestion limited", func() {
			sess.sentPacketHandler = &mockSentPacketHandler{congestionLimited: true}
			sess.packer.packetNumberGenerator.next = 0x1338
			packetNumber := protocol.PacketNumber(0x035e)
			sess.receivedPacketHandler.ReceivedPacket(packetNumber, true)
			err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring(string([]byte{0x03, 0x5e}))))
		})

		It("sends a retransmittable packet when required by the SentPacketHandler", func() {
			sess.sentPacketHandler = &mockSentPacketHandler{shouldSendRetransmittablePacket: true}
			sess.packer.QueueControlFrame(&wire.AckFrame{LargestAcked: 1000})
			err := sess.sendPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(sess.sentPacketHandler.(*mockSentPacketHandler).sentPackets[0].Frames).To(ContainElement(&wire.PingFrame{}))
		})

		It("sends public reset", func() {
			err := sess.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring("PRST")))
		})

		It("informs the SentPacketHandler about sent packets", func() {
			sess.sentPacketHandler = newMockSentPacketHandler()
			sess.packer.packetNumberGenerator.next = 0x1337 + 9
			sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}

			f := &wire.StreamFrame{
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
			Expect(sentPackets[0].EncryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
			Expect(mconn.written).To(HaveLen(1))
			Expect(sentPackets[0].Length).To(BeEquivalentTo(len(<-mconn.written)))
		})
	})

	Context("retransmissions", func() {
		var sph *mockSentPacketHandler
		BeforeEach(func() {
			// a StopWaitingFrame is added, so make sure the packet number of the new package is higher than the packet number of the retransmitted packet
			sess.packer.packetNumberGenerator.next = 0x1337 + 10
			sess.packer.hasSentPacket = true // make sure this is not the first packet the packer sends
			sph = newMockSentPacketHandler().(*mockSentPacketHandler)
			sess.sentPacketHandler = sph
			sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}
		})

		Context("for handshake packets", func() {
			It("retransmits an unencrypted packet", func() {
				sf := &wire.StreamFrame{StreamID: 1, Data: []byte("foobar")}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []wire.Frame{sf},
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
				swf := sentPackets[0].Frames[0].(*wire.StopWaitingFrame)
				Expect(swf.LeastUnacked).To(Equal(protocol.PacketNumber(0x1337)))
			})

			It("retransmit a packet encrypted with the initial encryption", func() {
				sf := &wire.StreamFrame{StreamID: 1, Data: []byte("foobar")}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []wire.Frame{sf},
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

			It("doesn't retransmit handshake packets when the handshake is complete", func() {
				sess.handshakeComplete = true
				sf := &wire.StreamFrame{StreamID: 1, Data: []byte("foobar")}
				sph.retransmissionQueue = []*ackhandler.Packet{{
					Frames:          []wire.Frame{sf},
					EncryptionLevel: protocol.EncryptionSecure,
				}}
				err := sess.sendPacket()
				Expect(err).ToNot(HaveOccurred())
				Expect(mconn.written).To(BeEmpty())
			})
		})

		Context("for packets after the handshake", func() {
			It("sends a StreamFrame from a packet queued for retransmission", func() {
				f := wire.StreamFrame{
					StreamID: 0x5,
					Data:     []byte("foobar1234567"),
				}
				p := ackhandler.Packet{
					PacketNumber:    0x1337,
					Frames:          []wire.Frame{&f},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				sph.retransmissionQueue = []*ackhandler.Packet{&p}

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				Expect(sph.requestedStopWaiting).To(BeTrue())
				Expect(mconn.written).To(Receive(ContainSubstring("foobar1234567")))
			})

			It("sends a StreamFrame from a packet queued for retransmission", func() {
				f1 := wire.StreamFrame{
					StreamID: 0x5,
					Data:     []byte("foobar"),
				}
				f2 := wire.StreamFrame{
					StreamID: 0x7,
					Data:     []byte("loremipsum"),
				}
				p1 := ackhandler.Packet{
					PacketNumber:    0x1337,
					Frames:          []wire.Frame{&f1},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				p2 := ackhandler.Packet{
					PacketNumber:    0x1338,
					Frames:          []wire.Frame{&f2},
					EncryptionLevel: protocol.EncryptionForwardSecure,
				}
				sph.retransmissionQueue = []*ackhandler.Packet{&p1, &p2}

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(1))
				packet := <-mconn.written
				Expect(packet).To(ContainSubstring("foobar"))
				Expect(packet).To(ContainSubstring("loremipsum"))
			})

			It("always attaches a StopWaiting to a packet that contains a retransmission", func() {
				f := &wire.StreamFrame{
					StreamID: 0x5,
					Data:     bytes.Repeat([]byte{'f'}, int(1.5*float32(protocol.MaxPacketSize))),
				}
				sess.streamFramer.AddFrameForRetransmission(f)

				err := sess.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(mconn.written).To(HaveLen(2))
				sentPackets := sph.sentPackets
				Expect(sentPackets).To(HaveLen(2))
				_, ok := sentPackets[0].Frames[0].(*wire.StopWaitingFrame)
				Expect(ok).To(BeTrue())
				_, ok = sentPackets[1].Frames[0].(*wire.StopWaitingFrame)
				Expect(ok).To(BeTrue())
			})
		})
	})

	It("retransmits RTO packets", func() {
		sess.packer.hasSentPacket = true // make sure this is not the first packet the packer sends
		sess.sentPacketHandler.SetHandshakeComplete()
		n := protocol.PacketNumber(10)
		sess.packer.cryptoSetup = &mockCryptoSetup{encLevelSeal: protocol.EncryptionForwardSecure}
		// We simulate consistently low RTTs, so that the test works faster
		rtt := time.Millisecond
		sess.rttStats.UpdateRTT(rtt, 0, time.Now())
		Expect(sess.rttStats.SmoothedRTT()).To(Equal(rtt)) // make sure it worked
		sess.packer.packetNumberGenerator.next = n + 1
		// Now, we send a single packet, and expect that it was retransmitted later
		err := sess.sentPacketHandler.SentPacket(&ackhandler.Packet{
			PacketNumber: n,
			Length:       1,
			Frames: []wire.Frame{&wire.StreamFrame{
				Data: []byte("foobar"),
			}},
			EncryptionLevel: protocol.EncryptionForwardSecure,
		})
		Expect(err).NotTo(HaveOccurred())
		go sess.run()
		defer sess.Close(nil)
		sess.scheduleSending()
		Eventually(func() int { return len(mconn.written) }).ShouldNot(BeZero())
		Expect(mconn.written).To(Receive(ContainSubstring("foobar")))
	})

	Context("scheduling sending", func() {
		BeforeEach(func() {
			sess.packer.hasSentPacket = true // make sure this is not the first packet the packer sends
			sess.processTransportParameters(&handshake.TransportParameters{
				StreamFlowControlWindow:     protocol.MaxByteCount,
				ConnectionFlowControlWindow: protocol.MaxByteCount,
				MaxStreams:                  1000,
			})
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
			s.(*stream).PopStreamFrame(1000) // unblock
		})

		It("sets the timer to the ack timer", func() {
			rph := &mockReceivedPacketHandler{ackAlarm: time.Now().Add(10 * time.Millisecond)}
			rph.nextAckFrame = &wire.AckFrame{LargestAcked: 0x1337}
			sess.receivedPacketHandler = rph
			go sess.run()
			defer sess.Close(nil)
			time.Sleep(10 * time.Millisecond)
			Eventually(func() int { return len(mconn.written) }).ShouldNot(BeZero())
			Expect(mconn.written).To(Receive(ContainSubstring(string([]byte{0x13, 0x37}))))
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

				Eventually(mconn.written).Should(HaveLen(1))
				packet := <-mconn.written
				Expect(packet).To(ContainSubstring("foobar1"))
				Expect(packet).To(ContainSubstring("foobar2"))
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
				Eventually(mconn.written).Should(HaveLen(2))
			})

			It("sends out two small frames that are written to long after one another into two packets", func() {
				s, err := sess.GetOrOpenStream(5)
				Expect(err).NotTo(HaveOccurred())
				go sess.run()
				defer sess.Close(nil)
				_, err = s.Write([]byte("foobar1"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(mconn.written).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())
				Eventually(mconn.written).Should(HaveLen(2))
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
				Eventually(mconn.written).Should(HaveLen(1))
				_, err = s.Write([]byte("foobar2"))
				Expect(err).NotTo(HaveOccurred())

				Eventually(mconn.written).Should(HaveLen(2))
				Expect(mconn.written).To(Receive(ContainSubstring(string([]byte{0x13, 0x37}))))
				Expect(mconn.written).ToNot(Receive(ContainSubstring(string([]byte{0x13, 0x37}))))
			})
		})
	})

	It("closes when crypto stream errors", func() {
		testErr := errors.New("crypto setup error")
		cryptoSetup.handleErr = testErr
		var runErr error
		go func() {
			runErr = sess.run()
		}()
		Eventually(func() error { return runErr }).Should(HaveOccurred())
		Expect(runErr).To(MatchError(testErr))
	})

	Context("sending a Public Reset when receiving undecryptable packets during the handshake", func() {
		// sends protocol.MaxUndecryptablePackets+1 undecrytable packets
		// this completely fills up the undecryptable packets queue and triggers the public reset timer
		sendUndecryptablePackets := func() {
			for i := 0; i < protocol.MaxUndecryptablePackets+1; i++ {
				hdr := &wire.Header{
					PacketNumber: protocol.PacketNumber(i + 1),
				}
				sess.handlePacket(&receivedPacket{
					header:     hdr,
					remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
					data:       []byte("foobar"),
				})
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
			Consistently(mconn.written).Should(HaveLen(0))
			Expect(sess.Close(nil)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sets a deadline to send a Public Reset after receiving too many undecryptable packets", func() {
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() time.Time { return sess.receivedTooManyUndecrytablePacketsTime }).Should(BeTemporally("~", time.Now(), 20*time.Millisecond))
			sess.Close(nil)
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("drops undecryptable packets when the undecrytable packet queue is full", func() {
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() []*receivedPacket { return sess.undecryptablePackets }).Should(HaveLen(protocol.MaxUndecryptablePackets))
			// check that old packets are kept, and the new packets are dropped
			Expect(sess.undecryptablePackets[0].header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			Expect(sess.Close(nil)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sends a Public Reset after a timeout", func() {
			Expect(sess.receivedTooManyUndecrytablePacketsTime).To(BeZero())
			go sess.run()
			sendUndecryptablePackets()
			Eventually(func() time.Time { return sess.receivedTooManyUndecrytablePacketsTime }).Should(BeTemporally("~", time.Now(), time.Second))
			// speed up this test by manually setting back the time when too many packets were received
			sess.receivedTooManyUndecrytablePacketsTime = time.Now().Add(-protocol.PublicResetTimeout)
			time.Sleep(10 * time.Millisecond) // wait for the run loop to spin up
			sess.scheduleSending()            // wake up the run loop
			Eventually(mconn.written).Should(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring("PRST")))
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("doesn't send a Public Reset if decrypting them suceeded during the timeout", func() {
			go sess.run()
			sess.receivedTooManyUndecrytablePacketsTime = time.Now().Add(-protocol.PublicResetTimeout).Add(-time.Millisecond)
			sess.scheduleSending() // wake up the run loop
			// there are no packets in the undecryptable packet queue
			// in reality, this happens when the trial decryption succeeded during the Public Reset timeout
			Consistently(mconn.written).ShouldNot(HaveLen(1))
			Expect(sess.Context().Done()).ToNot(Receive())
			Expect(sess.Close(nil)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("ignores undecryptable packets after the handshake is complete", func() {
			sess.handshakeComplete = true
			go sess.run()
			sendUndecryptablePackets()
			Consistently(sess.undecryptablePackets).Should(BeEmpty())
			Expect(sess.Close(nil)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("unqueues undecryptable packets for later decryption", func() {
			sess.undecryptablePackets = []*receivedPacket{{
				header: &wire.Header{PacketNumber: protocol.PacketNumber(42)},
			}}
			Expect(sess.receivedPackets).NotTo(Receive())
			sess.tryDecryptingQueuedPackets()
			Expect(sess.undecryptablePackets).To(BeEmpty())
			Expect(sess.receivedPackets).To(Receive())
		})
	})

	It("send a handshake event on the handshakeChan when the AEAD changes to secure", func(done Done) {
		go sess.run()
		aeadChanged <- protocol.EncryptionSecure
		Eventually(sess.handshakeStatus()).Should(Receive(&handshakeEvent{encLevel: protocol.EncryptionSecure}))
		Expect(sess.Close(nil)).To(Succeed())
		close(done)
	})

	It("send a handshake event on the handshakeChan when the AEAD changes to forward-secure", func(done Done) {
		go sess.run()
		aeadChanged <- protocol.EncryptionForwardSecure
		Eventually(sess.handshakeStatus()).Should(Receive(&handshakeEvent{encLevel: protocol.EncryptionForwardSecure}))
		Expect(sess.Close(nil)).To(Succeed())
		close(done)
	})

	It("closes the handshakeChan when the handshake completes", func(done Done) {
		go sess.run()
		close(aeadChanged)
		Eventually(sess.handshakeStatus()).Should(BeClosed())
		Expect(sess.Close(nil)).To(Succeed())
		close(done)
	})

	It("passes errors to the handshakeChan", func(done Done) {
		testErr := errors.New("handshake error")
		go sess.run()
		Expect(sess.Close(nil)).To(Succeed())
		Expect(sess.handshakeStatus()).To(Receive(&handshakeEvent{err: testErr}))
		close(done)
	})

	It("does not block if an error occurs", func(done Done) {
		// this test basically tests that the handshakeChan has a capacity of 3
		// The session needs to run (and close) properly, even if no one is receiving from the handshakeChan
		go sess.run()
		aeadChanged <- protocol.EncryptionSecure
		aeadChanged <- protocol.EncryptionForwardSecure
		Expect(sess.Close(nil)).To(Succeed())
		close(done)
	})

	It("process transport parameters received from the peer", func() {
		paramsChan := make(chan handshake.TransportParameters)
		sess.paramsChan = paramsChan
		_, err := sess.GetOrOpenStream(5)
		Expect(err).ToNot(HaveOccurred())
		go sess.run()
		params := handshake.TransportParameters{
			MaxStreams:                  123,
			IdleTimeout:                 90 * time.Second,
			StreamFlowControlWindow:     0x5000,
			ConnectionFlowControlWindow: 0x5000,
			OmitConnectionID:            true,
		}
		paramsChan <- params
		Eventually(func() *handshake.TransportParameters { return sess.peerParams }).Should(Equal(&params))
		Eventually(func() uint32 { return sess.streamsMap.maxOutgoingStreams }).Should(Equal(uint32(123)))
		// Eventually(func() (protocol.ByteCount, error) { return sess.flowControlManager.SendWindowSize(5) }).Should(Equal(protocol.ByteCount(0x5000)))
		Eventually(func() bool { return sess.packer.omitConnectionID }).Should(BeTrue())
		Expect(sess.Close(nil)).To(Succeed())
	})

	Context("keep-alives", func() {
		// should be shorter than the local timeout for these tests
		// otherwise we'd send a CONNECTION_CLOSE in the tests where we're testing that no PING is sent
		remoteIdleTimeout := 20 * time.Second

		BeforeEach(func() {
			sess.peerParams = &handshake.TransportParameters{IdleTimeout: remoteIdleTimeout}
		})

		It("sends a PING", func() {
			sess.handshakeComplete = true
			sess.config.KeepAlive = true
			sess.lastNetworkActivityTime = time.Now().Add(-remoteIdleTimeout / 2)
			sess.packer.hasSentPacket = true // make sure this is not the first packet the packer sends
			go sess.run()
			defer sess.Close(nil)
			var data []byte
			Eventually(mconn.written).Should(Receive(&data))
			// -12 because of the crypto tag. This should be 7 (the frame id for a ping frame).
			Expect(data[len(data)-12-1 : len(data)-12]).To(Equal([]byte{0x07}))
		})

		It("doesn't send a PING packet if keep-alive is disabled", func() {
			sess.handshakeComplete = true
			sess.config.KeepAlive = false
			sess.lastNetworkActivityTime = time.Now().Add(-remoteIdleTimeout / 2)
			go sess.run()
			defer sess.Close(nil)
			Consistently(mconn.written).ShouldNot(Receive())
		})

		It("doesn't send a PING if the handshake isn't completed yet", func() {
			sess.handshakeComplete = false
			sess.config.KeepAlive = true
			sess.lastNetworkActivityTime = time.Now().Add(-remoteIdleTimeout / 2)
			go sess.run()
			defer sess.Close(nil)
			Consistently(mconn.written).ShouldNot(Receive())
		})
	})

	Context("timeouts", func() {
		It("times out due to no network activity", func(done Done) {
			sess.handshakeComplete = true
			sess.lastNetworkActivityTime = time.Now().Add(-time.Hour)
			err := sess.run() // Would normally not return
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
			Expect(mconn.written).To(Receive(ContainSubstring("No recent network activity.")))
			Expect(sess.Context().Done()).To(BeClosed())
			close(done)
		})

		It("times out due to non-completed handshake", func(done Done) {
			sess.sessionCreationTime = time.Now().Add(-protocol.DefaultHandshakeTimeout).Add(-time.Second)
			err := sess.run() // Would normally not return
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.HandshakeTimeout))
			Expect(mconn.written).To(Receive(ContainSubstring("Crypto handshake did not complete in time.")))
			Expect(sess.Context().Done()).To(BeClosed())
			close(done)
		})

		It("does not use the idle timeout before the handshake complete", func() {
			sess.config.IdleTimeout = 9999 * time.Second
			defer sess.Close(nil)
			sess.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			// the handshake timeout is irrelevant here, since it depends on the time the session was created,
			// and not on the last network activity
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_ = sess.run()
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())
		})

		It("closes the session due to the idle timeout after handshake", func() {
			sess.config.IdleTimeout = 0
			close(aeadChanged)
			errChan := make(chan error)
			go func() {
				defer GinkgoRecover()
				errChan <- sess.run() // Would normally not return
			}()
			var err error
			Eventually(errChan).Should(Receive(&err))
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
			Expect(mconn.written).To(Receive(ContainSubstring("No recent network activity.")))
			Expect(sess.Context().Done()).To(BeClosed())
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
		BeforeEach(func() {
			sess.processTransportParameters(&handshake.TransportParameters{MaxStreams: 1000})
		})

		It("returns a new stream", func() {
			str, err := sess.GetOrOpenStream(11)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeNil())
			Expect(str.StreamID()).To(Equal(protocol.StreamID(11)))
		})

		It("returns a nil-value (not an interface with value nil) for closed streams", func() {
			str, err := sess.GetOrOpenStream(9)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
			str.(*stream).Cancel(nil)
			Expect(str.(*stream).Finished()).To(BeTrue())
			err = sess.streamsMap.DeleteClosedStreams()
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.streamsMap.GetOrOpenStream(9)).To(BeNil())
			str, err = sess.GetOrOpenStream(9)
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
			for i := 0; i < protocol.MaxIncomingStreams; i++ {
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
				Expect(s.Close()).To(Succeed())
				f := s.(*stream).PopStreamFrame(1000) // trigger "sending" of the FIN bit
				Expect(f.FinBit).To(BeTrue())
				s.(*stream).CloseRemote(0)
				_, err = s.Read([]byte("a"))
				Expect(err).To(MatchError(io.EOF))
				sess.streamsMap.DeleteClosedStreams()
			}
		})
	})

	Context("ignoring errors", func() {
		It("ignores duplicate acks", func() {
			sess.sentPacketHandler.SentPacket(&ackhandler.Packet{
				PacketNumber: 1,
				Length:       1,
			})
			err := sess.handleFrames([]wire.Frame{&wire.AckFrame{
				LargestAcked: 1,
			}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
			err = sess.handleFrames([]wire.Frame{&wire.AckFrame{
				LargestAcked: 1,
			}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// Context("window updates", func() {
	// 	It("gets stream level window updates", func() {
	// 		_, err := sess.GetOrOpenStream(3)
	// 		Expect(err).ToNot(HaveOccurred())
	// 		err = sess.flowControlManager.AddBytesRead(3, protocol.ReceiveStreamFlowControlWindow)
	// 		Expect(err).NotTo(HaveOccurred())
	// 		frames := sess.getWindowUpdateFrames()
	// 		Expect(frames).To(HaveLen(1))
	// 		Expect(frames[0].StreamID).To(Equal(protocol.StreamID(3)))
	// 		Expect(frames[0].ByteOffset).To(BeEquivalentTo(protocol.ReceiveStreamFlowControlWindow * 2))
	// 	})

	// 	It("gets connection level window updates", func() {
	// 		_, err := sess.GetOrOpenStream(5)
	// 		Expect(err).NotTo(HaveOccurred())
	// 		err = sess.flowControlManager.AddBytesRead(5, protocol.ReceiveConnectionFlowControlWindow)
	// 		Expect(err).NotTo(HaveOccurred())
	// 		frames := sess.getWindowUpdateFrames()
	// 		Expect(frames).To(HaveLen(1))
	// 		Expect(frames[0].StreamID).To(Equal(protocol.StreamID(0)))
	// 		Expect(frames[0].ByteOffset).To(BeEquivalentTo(protocol.ReceiveConnectionFlowControlWindow * 2))
	// 	})
	// })

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

var _ = Describe("Client Session", func() {
	var (
		sess        *session
		mconn       *mockConnection
		aeadChanged chan<- protocol.EncryptionLevel

		cryptoSetup *mockCryptoSetup
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		cryptoSetup = &mockCryptoSetup{}
		newCryptoSetupClient = func(
			_ io.ReadWriter,
			_ string,
			_ protocol.ConnectionID,
			_ protocol.VersionNumber,
			_ *tls.Config,
			_ *handshake.TransportParameters,
			_ chan<- handshake.TransportParameters,
			aeadChangedP chan<- protocol.EncryptionLevel,
			_ protocol.VersionNumber,
			_ []protocol.VersionNumber,
		) (handshake.CryptoSetup, error) {
			aeadChanged = aeadChangedP
			return cryptoSetup, nil
		}

		mconn = newMockConnection()
		sessP, err := newClientSession(
			mconn,
			"hostname",
			protocol.Version39,
			0,
			nil,
			populateClientConfig(&Config{}),
			protocol.VersionWhatever,
			nil,
		)
		sess = sessP.(*session)
		Expect(err).ToNot(HaveOccurred())
		Expect(sess.streamsMap.openStreams).To(BeEmpty())
	})

	AfterEach(func() {
		newCryptoSetupClient = handshake.NewCryptoSetupClient
	})

	Context("receiving packets", func() {
		var hdr *wire.Header

		BeforeEach(func() {
			hdr = &wire.Header{PacketNumberLen: protocol.PacketNumberLen6}
			sess.unpacker = &mockUnpacker{}
		})

		It("passes the diversification nonce to the cryptoSetup", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			hdr.PacketNumber = 5
			hdr.DiversificationNonce = []byte("foobar")
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() []byte { return cryptoSetup.divNonce }).Should(Equal(hdr.DiversificationNonce))
			Expect(sess.Close(nil)).To(Succeed())
		})
	})

	It("does not block if an error occurs", func(done Done) {
		// this test basically tests that the handshakeChan has a capacity of 3
		// The session needs to run (and close) properly, even if no one is receiving from the handshakeChan
		go sess.run()
		aeadChanged <- protocol.EncryptionSecure
		aeadChanged <- protocol.EncryptionForwardSecure
		Expect(sess.Close(nil)).To(Succeed())
		close(done)
	})
})
