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

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/mocks/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
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

type mockCryptoSetup struct {
	handleErr error
	divNonce  []byte
}

var _ handshake.CryptoSetup = &mockCryptoSetup{}

func (m *mockCryptoSetup) RunHandshake() error { return m.handleErr }
func (m *mockCryptoSetup) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	panic("not implemented")
}
func (m *mockCryptoSetup) GetSealer() (protocol.EncryptionLevel, handshake.Sealer) {
	panic("not implemented")
}
func (m *mockCryptoSetup) GetSealerForCryptoStream() (protocol.EncryptionLevel, handshake.Sealer) {
	panic("not implemented")
}
func (m *mockCryptoSetup) GetSealerWithEncryptionLevel(protocol.EncryptionLevel) (handshake.Sealer, error) {
	panic("not implemented")
}
func (m *mockCryptoSetup) SetDiversificationNonce(divNonce []byte) error {
	m.divNonce = divNonce
	return nil
}
func (m *mockCryptoSetup) ConnectionState() ConnectionState { panic("not implemented") }

func areSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*session).run")
}

var _ = Describe("Session", func() {
	var (
		sess                  *session
		sessionRunner         *MockSessionRunner
		scfg                  *handshake.ServerConfig
		mconn                 *mockConnection
		cryptoSetup           *mockCryptoSetup
		streamManager         *MockStreamManager
		packer                *MockPacker
		handshakeChan         chan<- struct{}
		handshakeCompleteChan chan<- struct{}
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		cryptoSetup = &mockCryptoSetup{}
		newCryptoSetup = func(
			_ io.ReadWriter,
			_ protocol.ConnectionID,
			_ net.Addr,
			_ protocol.VersionNumber,
			_ []byte,
			_ *handshake.ServerConfig,
			_ *handshake.TransportParameters,
			_ []protocol.VersionNumber,
			_ func(net.Addr, *Cookie) bool,
			_ chan<- handshake.TransportParameters,
			handshakeChanP chan<- struct{},
			handshakeCompleteChanP chan<- struct{},
			_ utils.Logger,
		) (handshake.CryptoSetup, error) {
			handshakeChan = handshakeChanP
			handshakeCompleteChan = handshakeCompleteChanP
			return cryptoSetup, nil
		}

		sessionRunner = NewMockSessionRunner(mockCtrl)
		mconn = newMockConnection()
		certChain := crypto.NewCertChain(testdata.GetTLSConfig())
		kex, err := crypto.NewCurve25519KEX()
		Expect(err).NotTo(HaveOccurred())
		scfg, err = handshake.NewServerConfig(kex, certChain)
		Expect(err).NotTo(HaveOccurred())
		var pSess Session
		pSess, err = newSession(
			mconn,
			sessionRunner,
			protocol.Version39,
			protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
			protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
			scfg,
			nil,
			populateServerConfig(&Config{}),
			utils.DefaultLogger,
		)
		Expect(err).NotTo(HaveOccurred())
		sess = pSess.(*session)
		streamManager = NewMockStreamManager(mockCtrl)
		sess.streamsMap = streamManager
		packer = NewMockPacker(mockCtrl)
		sess.packer = packer
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
				_ []byte,
				_ *handshake.ServerConfig,
				_ *handshake.TransportParameters,
				_ []protocol.VersionNumber,
				cookieFunc func(net.Addr, *Cookie) bool,
				_ chan<- handshake.TransportParameters,
				_ chan<- struct{},
				_ chan<- struct{},
				_ utils.Logger,
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
				sessionRunner,
				protocol.Version39,
				protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
				protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
				scfg,
				nil,
				conf,
				utils.DefaultLogger,
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
		Context("handling STREAM frames", func() {
			It("passes STREAM frames to the stream", func() {
				f := &wire.StreamFrame{
					StreamID: 5,
					Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				}
				str := NewMockReceiveStreamI(mockCtrl)
				str.EXPECT().handleStreamFrame(f)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(str, nil)
				err := sess.handleStreamFrame(f, protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				testErr := errors.New("test err")
				f := &wire.StreamFrame{
					StreamID: 5,
					Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				}
				str := NewMockReceiveStreamI(mockCtrl)
				str.EXPECT().handleStreamFrame(f).Return(testErr)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(str, nil)
				err := sess.handleStreamFrame(f, protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError(testErr))
			})

			It("ignores STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(nil, nil) // for closed streams, the streamManager returns nil
				err := sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar"),
				}, protocol.EncryptionForwardSecure)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors on a STREAM frame that would close the crypto stream", func() {
				err := sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: 1,
					Offset:   0x1337,
					FinBit:   true,
				}, protocol.EncryptionForwardSecure)
				Expect(err).To(MatchError("Received STREAM frame with FIN bit for the crypto stream"))
			})

			It("accepts unencrypted STREAM frames on the crypto stream", func() {
				f := &wire.StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
				}
				str := NewMockStreamI(mockCtrl)
				str.EXPECT().handleStreamFrame(f)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(1)).Return(str, nil) // for closed streams, the streamManager returns nil
				err := sess.handleStreamFrame(f, protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
			})

			It("does not handle unencrypted STREAM frames on higher streams", func() {
				err := sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: 3,
					Data:     []byte("foobar"),
				}, protocol.EncryptionUnencrypted)
				Expect(err).To(MatchError(qerr.Error(qerr.UnencryptedStreamData, "received unencrypted stream data on stream 3")))
			})
		})

		Context("handling ACK frames", func() {
			It("informs the SentPacketHandler about ACKs", func() {
				f := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}}
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().ReceivedAck(f, protocol.PacketNumber(42), protocol.EncryptionSecure, gomock.Any())
				sph.EXPECT().GetLowestPacketNotConfirmedAcked()
				sess.sentPacketHandler = sph
				sess.lastRcvdPacketNumber = 42
				err := sess.handleAckFrame(f, protocol.EncryptionSecure)
				Expect(err).ToNot(HaveOccurred())
			})

			It("tells the ReceivedPacketHandler to ignore low ranges", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}}
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().ReceivedAck(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				sph.EXPECT().GetLowestPacketNotConfirmedAcked().Return(protocol.PacketNumber(0x42))
				sess.sentPacketHandler = sph
				rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
				rph.EXPECT().IgnoreBelow(protocol.PacketNumber(0x42))
				sess.receivedPacketHandler = rph
				err := sess.handleAckFrame(ack, protocol.EncryptionUnencrypted)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("handling RST_STREAM frames", func() {
			It("closes the streams for writing", func() {
				f := &wire.RstStreamFrame{
					StreamID:   555,
					ErrorCode:  42,
					ByteOffset: 0x1337,
				}
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(555)).Return(str, nil)
				str.EXPECT().handleRstStreamFrame(f)
				err := sess.handleRstStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				f := &wire.RstStreamFrame{
					StreamID:   7,
					ByteOffset: 0x1337,
				}
				testErr := errors.New("flow control violation")
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(7)).Return(str, nil)
				str.EXPECT().handleRstStreamFrame(f).Return(testErr)
				err := sess.handleRstStreamFrame(f)
				Expect(err).To(MatchError(testErr))
			})

			It("ignores RST_STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(3)).Return(nil, nil)
				err := sess.handleFrames([]wire.Frame{&wire.RstStreamFrame{
					StreamID:  3,
					ErrorCode: 42,
				}}, protocol.EncryptionUnspecified)
				Expect(err).NotTo(HaveOccurred())
			})

			It("erros when a RST_STREAM frame would reset the crypto stream", func() {
				err := sess.handleRstStreamFrame(&wire.RstStreamFrame{
					StreamID:  1,
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

			It("updates the flow control window of a stream", func() {
				f := &wire.MaxStreamDataFrame{
					StreamID:   12345,
					ByteOffset: 0x1337,
				}
				str := NewMockSendStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(12345)).Return(str, nil)
				str.EXPECT().handleMaxStreamDataFrame(f)
				err := sess.handleMaxStreamDataFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("updates the flow control window of the connection", func() {
				offset := protocol.ByteCount(0x800000)
				connFC.EXPECT().UpdateSendWindow(offset)
				sess.handleMaxDataFrame(&wire.MaxDataFrame{ByteOffset: offset})
			})

			It("ignores MAX_STREAM_DATA frames for a closed stream", func() {
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(10)).Return(nil, nil)
				err := sess.handleFrames([]wire.Frame{&wire.MaxStreamDataFrame{
					StreamID:   10,
					ByteOffset: 1337,
				}}, protocol.EncryptionUnspecified)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("handling MAX_STREAM_ID frames", func() {
			It("passes the frame to the streamsMap", func() {
				f := &wire.MaxStreamIDFrame{StreamID: 10}
				streamManager.EXPECT().HandleMaxStreamIDFrame(f)
				err := sess.handleMaxStreamIDFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				f := &wire.MaxStreamIDFrame{StreamID: 10}
				testErr := errors.New("test error")
				streamManager.EXPECT().HandleMaxStreamIDFrame(f).Return(testErr)
				err := sess.handleMaxStreamIDFrame(f)
				Expect(err).To(MatchError(testErr))
			})
		})

		Context("handling STOP_SENDING frames", func() {
			It("passes the frame to the stream", func() {
				f := &wire.StopSendingFrame{
					StreamID:  5,
					ErrorCode: 10,
				}
				str := NewMockSendStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(5)).Return(str, nil)
				str.EXPECT().handleStopSendingFrame(f)
				err := sess.handleStopSendingFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors when receiving a STOP_SENDING for the crypto stream", func() {
				err := sess.handleStopSendingFrame(&wire.StopSendingFrame{
					StreamID:  1,
					ErrorCode: 10,
				})
				Expect(err).To(MatchError("Received a STOP_SENDING frame for the crypto stream"))
			})

			It("ignores STOP_SENDING frames for a closed stream", func() {
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(3)).Return(nil, nil)
				err := sess.handleFrames([]wire.Frame{&wire.StopSendingFrame{
					StreamID:  3,
					ErrorCode: 1337,
				}}, protocol.EncryptionUnspecified)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		It("handles PING frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.PingFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects PATH_RESPONSE frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}}, protocol.EncryptionUnspecified)
			Expect(err).To(MatchError("unexpected PATH_RESPONSE frame"))
		})

		It("handles PATH_CHALLENGE frames", func() {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			err := sess.handleFrames([]wire.Frame{&wire.PathChallengeFrame{Data: data}}, protocol.EncryptionUnspecified)
			Expect(err).ToNot(HaveOccurred())
			frames, _ := sess.framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{&wire.PathResponseFrame{Data: data}}))
		})

		It("handles BLOCKED frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.BlockedFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAM_BLOCKED frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.StreamBlockedFrame{}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAM_ID_BLOCKED frames", func() {
			err := sess.handleFrames([]wire.Frame{&wire.StreamIDBlockedFrame{}}, protocol.EncryptionUnspecified)
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
			testErr := qerr.Error(qerr.ProofInvalid, "foobar")
			streamManager.EXPECT().CloseWithError(testErr)
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err).To(MatchError(testErr))
			}()
			err := sess.handleFrames([]wire.Frame{&wire.ConnectionCloseFrame{ErrorCode: qerr.ProofInvalid, ReasonPhrase: "foobar"}}, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})
	})

	It("tells its versions", func() {
		sess.version = 4242
		Expect(sess.GetVersion()).To(Equal(protocol.VersionNumber(4242)))
	})

	It("accepts new streams", func() {
		mstr := NewMockStreamI(mockCtrl)
		streamManager.EXPECT().AcceptStream().Return(mstr, nil)
		str, err := sess.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		Expect(str).To(Equal(mstr))
	})

	Context("closing", func() {
		BeforeEach(func() {
			Eventually(areSessionsRunning).Should(BeFalse())
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			Eventually(areSessionsRunning).Should(BeTrue())
		})

		It("shuts down without error", func() {
			streamManager.EXPECT().CloseWithError(qerr.Error(qerr.PeerGoingAway, ""))
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{raw: []byte("connection close")}, nil)
			Expect(sess.Close()).To(Succeed())
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring("connection close")))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("only closes once", func() {
			streamManager.EXPECT().CloseWithError(qerr.Error(qerr.PeerGoingAway, ""))
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			Expect(sess.Close()).To(Succeed())
			Expect(sess.Close()).To(Succeed())
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			streamManager.EXPECT().CloseWithError(qerr.Error(0x1337, testErr.Error()))
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.CloseWithError(0x1337, testErr)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes the session in order to replace it with another QUIC version", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.destroy(errCloseSessionForNewVersion)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(BeEmpty()) // no CONNECTION_CLOSE or PUBLIC_RESET sent
		})

		It("sends a Public Reset if the client is initiating the no STOP_WAITING experiment", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.closeLocal(handshake.ErrNSTPExperiment)
			Eventually(mconn.written).Should(HaveLen(1))
			Expect((<-mconn.written)[0] & 0x02).ToNot(BeZero()) // Public Reset
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("cancels the context when the run loop exists", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			returned := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ctx := sess.Context()
				<-ctx.Done()
				Expect(ctx.Err()).To(MatchError(context.Canceled))
				close(returned)
			}()
			Consistently(returned).ShouldNot(BeClosed())
			sess.Close()
			Eventually(returned).Should(BeClosed())
		})
	})

	Context("receiving packets", func() {
		var hdr *wire.Header
		var unpacker *MockUnpacker

		BeforeEach(func() {
			unpacker = NewMockUnpacker(mockCtrl)
			sess.unpacker = unpacker
			hdr = &wire.Header{PacketNumberLen: protocol.PacketNumberLen6}
		})

		It("sets the {last,largest}RcvdPacketNumber", func() {
			hdr.PacketNumber = 5
			hdr.Raw = []byte("raw header")
			unpacker.EXPECT().Unpack([]byte("raw header"), hdr, []byte("foobar")).Return(&unpackedPacket{}, nil)
			err := sess.handlePacketImpl(&receivedPacket{header: hdr, data: []byte("foobar")})
			Expect(err).ToNot(HaveOccurred())
			Expect(sess.lastRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
			Expect(sess.largestRcvdPacketNumber).To(Equal(protocol.PacketNumber(5)))
		})

		It("informs the ReceivedPacketHandler", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
			now := time.Now().Add(time.Hour)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().ReceivedPacket(protocol.PacketNumber(5), now, false)
			sess.receivedPacketHandler = rph
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{header: hdr, rcvTime: now})
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't inform the ReceivedPacketHandler about Retry packets", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
			now := time.Now().Add(time.Hour)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			sess.receivedPacketHandler = rph
			// don't EXPECT any call to ReceivedPacket
			hdr.PacketNumber = 5
			hdr.Type = protocol.PacketTypeRetry
			err := sess.handlePacketImpl(&receivedPacket{header: hdr, rcvTime: now})
			Expect(err).ToNot(HaveOccurred())
		})

		It("closes when handling a packet fails", func() {
			testErr := errors.New("unpack error")
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, testErr)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			hdr.PacketNumber = 5
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err).To(MatchError(testErr))
				close(done)
			}()
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.handlePacket(&receivedPacket{header: hdr})
			Eventually(done).Should(BeClosed())
		})

		It("sets the {last,largest}RcvdPacketNumber, for an out-of-order packet", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil).Times(2)
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
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil).Times(2)
			hdr.PacketNumber = 5
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			err = sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
		})

		It("ignores packets with a different source connection ID", func() {
			// Send one packet, which might change the connection ID.
			// only EXPECT one call to the unpacker
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
			err := sess.handlePacketImpl(&receivedPacket{
				header: &wire.Header{
					IsLongHeader:     true,
					DestConnectionID: sess.destConnID,
					SrcConnectionID:  sess.srcConnID,
				},
			})
			Expect(err).ToNot(HaveOccurred())
			// The next packet has to be ignored, since the source connection ID doesn't match.
			err = sess.handlePacketImpl(&receivedPacket{
				header: &wire.Header{
					IsLongHeader:     true,
					DestConnectionID: sess.destConnID,
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
				},
			})
			Expect(err).ToNot(HaveOccurred())
		})

		Context("updating the remote address", func() {
			It("doesn't support connection migration", func() {
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
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
		})
	})

	Context("sending packets", func() {
		getPacket := func(pn protocol.PacketNumber) *packedPacket {
			data := *getPacketBuffer()
			data = append(data, []byte("foobar")...)
			return &packedPacket{
				raw:    data,
				header: &wire.Header{PacketNumber: pn},
			}
		}

		It("sends packets", func() {
			packer.EXPECT().PackPacket().Return(getPacket(1), nil)
			err := sess.receivedPacketHandler.ReceivedPacket(0x035e, time.Now(), true)
			Expect(err).ToNot(HaveOccurred())
			sent, err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
		})

		It("doesn't send packets if there's nothing to send", func() {
			packer.EXPECT().PackPacket().Return(getPacket(2), nil)
			err := sess.receivedPacketHandler.ReceivedPacket(0x035e, time.Now(), true)
			Expect(err).ToNot(HaveOccurred())
			sent, err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
		})

		It("sends ACK only packets", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetAlarmTimeout().AnyTimes()
			sph.EXPECT().SendMode().Return(ackhandler.SendAck)
			sph.EXPECT().ShouldSendNumPackets().Return(1000)
			packer.EXPECT().MaybePackAckPacket()
			sess.sentPacketHandler = sph
			Expect(sess.sendPackets()).To(Succeed())
		})

		It("adds a BLOCKED frame when it is connection-level flow control blocked", func() {
			fc := mocks.NewMockConnectionFlowController(mockCtrl)
			fc.EXPECT().IsNewlyBlocked().Return(true, protocol.ByteCount(1337))
			packer.EXPECT().PackPacket().Return(getPacket(1), nil)
			sess.connFlowController = fc
			sent, err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
			frames, _ := sess.framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(Equal([]wire.Frame{&wire.BlockedFrame{Offset: 1337}}))
		})

		It("sends PUBLIC_RESET", func() {
			err := sess.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring("PRST")))
		})

		It("sends a retransmission and a regular packet in the same run", func() {
			packetToRetransmit := &ackhandler.Packet{
				PacketNumber: 10,
				PacketType:   protocol.PacketTypeHandshake,
			}
			retransmittedPacket := getPacket(123)
			newPacket := getPacket(234)
			sess.windowUpdateQueue.callback(&wire.MaxDataFrame{})
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetPacketNumberLen(gomock.Any()).Return(protocol.PacketNumberLen2).AnyTimes()
			sph.EXPECT().DequeuePacketForRetransmission().Return(packetToRetransmit)
			sph.EXPECT().SendMode().Return(ackhandler.SendRetransmission)
			sph.EXPECT().SendMode().Return(ackhandler.SendAny)
			sph.EXPECT().ShouldSendNumPackets().Return(2)
			sph.EXPECT().TimeUntilSend()
			gomock.InOrder(
				packer.EXPECT().PackRetransmission(packetToRetransmit).Return([]*packedPacket{retransmittedPacket}, nil),
				sph.EXPECT().SentPacketsAsRetransmission(gomock.Any(), protocol.PacketNumber(10)).Do(func(packets []*ackhandler.Packet, _ protocol.PacketNumber) {
					Expect(packets).To(HaveLen(1))
					Expect(packets[0].PacketNumber).To(Equal(protocol.PacketNumber(123)))
				}),
				packer.EXPECT().PackPacket().Return(newPacket, nil),
				sph.EXPECT().SentPacket(gomock.Any()).Do(func(p *ackhandler.Packet) {
					Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(234)))
				}),
			)
			sess.sentPacketHandler = sph
			Expect(sess.sendPackets()).To(Succeed())
		})

		It("sends multiple packets, if the retransmission is split", func() {
			sess.version = versionIETFFrames
			packet := &ackhandler.Packet{
				PacketNumber: 42,
				Frames: []wire.Frame{&wire.StreamFrame{
					StreamID: 0x5,
					Data:     []byte("foobar"),
				}},
				EncryptionLevel: protocol.EncryptionForwardSecure,
			}
			retransmissions := []*packedPacket{getPacket(1337), getPacket(1338)}
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().DequeuePacketForRetransmission().Return(packet)
			packer.EXPECT().PackRetransmission(packet).Return(retransmissions, nil)
			sph.EXPECT().SentPacketsAsRetransmission(gomock.Any(), protocol.PacketNumber(42)).Do(func(packets []*ackhandler.Packet, _ protocol.PacketNumber) {
				Expect(packets).To(HaveLen(2))
				Expect(packets[0].PacketNumber).To(Equal(protocol.PacketNumber(1337)))
				Expect(packets[1].PacketNumber).To(Equal(protocol.PacketNumber(1338)))
			})
			sess.sentPacketHandler = sph
			sent, err := sess.maybeSendRetransmission()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
			Expect(mconn.written).To(HaveLen(2))
		})

		It("sends a probe packet", func() {
			packetToRetransmit := &ackhandler.Packet{
				PacketNumber: 0x42,
				PacketType:   protocol.PacketTypeHandshake,
			}
			retransmittedPacket := getPacket(123)
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().TimeUntilSend()
			sph.EXPECT().GetPacketNumberLen(gomock.Any()).Return(protocol.PacketNumberLen2).AnyTimes()
			sph.EXPECT().SendMode().Return(ackhandler.SendTLP)
			sph.EXPECT().ShouldSendNumPackets().Return(1)
			sph.EXPECT().DequeueProbePacket().Return(packetToRetransmit, nil)
			packer.EXPECT().PackRetransmission(packetToRetransmit).Return([]*packedPacket{retransmittedPacket}, nil)
			sph.EXPECT().SentPacketsAsRetransmission(gomock.Any(), protocol.PacketNumber(0x42)).Do(func(packets []*ackhandler.Packet, _ protocol.PacketNumber) {
				Expect(packets).To(HaveLen(1))
				Expect(packets[0].PacketNumber).To(Equal(protocol.PacketNumber(123)))
			})
			sess.sentPacketHandler = sph
			Expect(sess.sendPackets()).To(Succeed())
		})

		It("doesn't send when the SentPacketHandler doesn't allow it", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().SendMode().Return(ackhandler.SendNone)
			sess.sentPacketHandler = sph
			err := sess.sendPackets()
			Expect(err).ToNot(HaveOccurred())
		})

		Context("packet pacing", func() {
			var sph *mockackhandler.MockSentPacketHandler

			BeforeEach(func() {
				sph = mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().GetAlarmTimeout().AnyTimes()
				sph.EXPECT().GetPacketNumberLen(gomock.Any()).Return(protocol.PacketNumberLen2).AnyTimes()
				sph.EXPECT().DequeuePacketForRetransmission().AnyTimes()
				sess.sentPacketHandler = sph
				streamManager.EXPECT().CloseWithError(gomock.Any())
			})

			It("sends multiple packets one by one immediately", func() {
				sph.EXPECT().SentPacket(gomock.Any()).Times(2)
				sph.EXPECT().ShouldSendNumPackets().Return(1).Times(2)
				sph.EXPECT().TimeUntilSend().Return(time.Now()).Times(2)
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).Times(2) // allow 2 packets...
				packer.EXPECT().PackPacket().Return(getPacket(10), nil)
				packer.EXPECT().PackPacket().Return(getPacket(11), nil)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess.run()
					close(done)
				}()
				sess.scheduleSending()
				Eventually(mconn.written).Should(HaveLen(2))
				Consistently(mconn.written).Should(HaveLen(2))
				// make the go routine return
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				sess.Close()
				Eventually(done).Should(BeClosed())
			})

			// when becoming congestion limited, at some point the SendMode will change from SendAny to SendAck
			// we shouldn't send the ACK in the same run
			It("doesn't send an ACK right after becoming congestion limited", func() {
				sph.EXPECT().SentPacket(gomock.Any())
				sph.EXPECT().ShouldSendNumPackets().Return(1000)
				sph.EXPECT().TimeUntilSend().Return(time.Now())
				sph.EXPECT().SendMode().Return(ackhandler.SendAny)
				sph.EXPECT().SendMode().Return(ackhandler.SendAck)
				packer.EXPECT().PackPacket().Return(getPacket(100), nil)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess.run()
					close(done)
				}()
				sess.scheduleSending()
				Eventually(mconn.written).Should(HaveLen(1))
				Consistently(mconn.written).Should(HaveLen(1))
				// make the go routine return
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				sess.Close()
				Eventually(done).Should(BeClosed())
			})

			It("paces packets", func() {
				pacingDelay := scaleDuration(100 * time.Millisecond)
				sph.EXPECT().SentPacket(gomock.Any()).Times(2)
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(-time.Minute)) // send one packet immediately
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(pacingDelay))  // send one
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
				sph.EXPECT().ShouldSendNumPackets().Times(2).Return(1)
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
				packer.EXPECT().PackPacket().Return(getPacket(100), nil)
				packer.EXPECT().PackPacket().Return(getPacket(101), nil)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess.run()
					close(done)
				}()
				sess.scheduleSending()
				Eventually(mconn.written).Should(HaveLen(1))
				Consistently(mconn.written, pacingDelay/2).Should(HaveLen(1))
				Eventually(mconn.written, 2*pacingDelay).Should(HaveLen(2))
				// make the go routine return
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				sess.Close()
				Eventually(done).Should(BeClosed())
			})

			It("sends multiple packets at once", func() {
				sph.EXPECT().SentPacket(gomock.Any()).Times(3)
				sph.EXPECT().ShouldSendNumPackets().Return(3)
				sph.EXPECT().TimeUntilSend().Return(time.Now())
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).Times(3)
				packer.EXPECT().PackPacket().Return(getPacket(1000), nil)
				packer.EXPECT().PackPacket().Return(getPacket(1001), nil)
				packer.EXPECT().PackPacket().Return(getPacket(1002), nil)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess.run()
					close(done)
				}()
				sess.scheduleSending()
				Eventually(mconn.written).Should(HaveLen(3))
				// make the go routine return
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				sess.Close()
				Eventually(done).Should(BeClosed())
			})

			It("doesn't set a pacing timer when there is no data to send", func() {
				sph.EXPECT().TimeUntilSend().Return(time.Now())
				sph.EXPECT().ShouldSendNumPackets().Return(1)
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
				packer.EXPECT().PackPacket()
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess.run()
					close(done)
				}()
				sess.scheduleSending() // no packet will get sent
				Consistently(mconn.written).ShouldNot(Receive())
				// make the go routine return
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sess.Close()
				Eventually(done).Should(BeClosed())
			})
		})

		Context("scheduling sending", func() {
			It("sends when scheduleSending is called", func() {
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().GetAlarmTimeout().AnyTimes()
				sph.EXPECT().TimeUntilSend().AnyTimes()
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
				sph.EXPECT().ShouldSendNumPackets().AnyTimes().Return(1)
				sph.EXPECT().GetPacketNumberLen(gomock.Any()).Return(protocol.PacketNumberLen2).AnyTimes()
				sph.EXPECT().SentPacket(gomock.Any())
				sess.sentPacketHandler = sph
				packer.EXPECT().PackPacket().Return(getPacket(1), nil)

				go func() {
					defer GinkgoRecover()
					sess.run()
				}()
				Consistently(mconn.written).ShouldNot(Receive())
				sess.scheduleSending()
				Eventually(mconn.written).Should(Receive())
				// make the go routine return
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				streamManager.EXPECT().CloseWithError(gomock.Any())
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sess.Close()
				Eventually(sess.Context().Done()).Should(BeClosed())
			})

			It("sets the timer to the ack timer", func() {
				packer.EXPECT().PackPacket().Return(getPacket(1234), nil)
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().TimeUntilSend().Return(time.Now())
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
				sph.EXPECT().GetAlarmTimeout().AnyTimes()
				sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
				sph.EXPECT().ShouldSendNumPackets().Return(1)
				sph.EXPECT().SentPacket(gomock.Any()).Do(func(p *ackhandler.Packet) {
					Expect(p.PacketNumber).To(Equal(protocol.PacketNumber(1234)))
				})
				sess.sentPacketHandler = sph
				rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
				rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(10 * time.Millisecond))
				// make the run loop wait
				rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(time.Hour)).MaxTimes(1)
				sess.receivedPacketHandler = rph

				go func() {
					defer GinkgoRecover()
					sess.run()
				}()
				Eventually(mconn.written).Should(Receive())
				// make sure the go routine returns
				packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
				sessionRunner.EXPECT().removeConnectionID(gomock.Any())
				streamManager.EXPECT().CloseWithError(gomock.Any())
				sess.Close()
				Eventually(sess.Context().Done()).Should(BeClosed())
			})
		})
	})

	It("closes when crypto stream errors", func() {
		testErr := errors.New("crypto setup error")
		streamManager.EXPECT().CloseWithError(qerr.Error(qerr.InternalError, testErr.Error()))
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.handleErr = testErr
		go func() {
			defer GinkgoRecover()
			err := sess.run()
			Expect(err).To(MatchError(testErr))
		}()
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	Context("sending a PUBLIC_RESET when receiving undecryptable packets during the handshake", func() {
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
			unpacker := NewMockUnpacker(mockCtrl)
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, qerr.Error(qerr.DecryptionFailure, "")).AnyTimes()
			sess.unpacker = unpacker
			sess.cryptoStreamHandler = &mockCryptoSetup{}
			streamManager.EXPECT().CloseWithError(gomock.Any()).MaxTimes(1)
			packer.EXPECT().PackPacket().AnyTimes()
		})

		It("doesn't immediately send a PUBLIC_RESET after receiving too many undecryptable packets", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			sendUndecryptablePackets()
			sess.scheduleSending()
			Consistently(mconn.written).Should(HaveLen(0))
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sets a deadline to send a PUBLIC_RESET after receiving too many undecryptable packets", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			sendUndecryptablePackets()
			Eventually(func() time.Time { return sess.receivedTooManyUndecrytablePacketsTime }).Should(BeTemporally("~", time.Now(), 20*time.Millisecond))
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("drops undecryptable packets when the undecrytable packet queue is full", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			sendUndecryptablePackets()
			Eventually(func() []*receivedPacket { return sess.undecryptablePackets }).Should(HaveLen(protocol.MaxUndecryptablePackets))
			// check that old packets are kept, and the new packets are dropped
			Expect(sess.undecryptablePackets[0].header.PacketNumber).To(Equal(protocol.PacketNumber(1)))
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			Expect(sess.Close()).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sends a PUBLIC_RESET after a timeout", func() {
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			Expect(sess.receivedTooManyUndecrytablePacketsTime).To(BeZero())
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
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

		It("doesn't send a PUBLIC_RESET if decrypting them succeeded during the timeout", func() {
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			sess.receivedTooManyUndecrytablePacketsTime = time.Now().Add(-protocol.PublicResetTimeout).Add(-time.Millisecond)
			sess.scheduleSending() // wake up the run loop
			// there are no packets in the undecryptable packet queue
			// in reality, this happens when the trial decryption succeeded during the Public Reset timeout
			Consistently(mconn.written).ShouldNot(HaveLen(1))
			Expect(sess.Context().Done()).ToNot(Receive())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("ignores undecryptable packets after the handshake is complete", func() {
			sess.handshakeComplete = true
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			sendUndecryptablePackets()
			Consistently(sess.undecryptablePackets).Should(BeEmpty())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			Expect(sess.Close()).To(Succeed())
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

	It("doesn't do anything when the crypto setup says to decrypt undecryptable packets", func() {
		go func() {
			defer GinkgoRecover()
			sess.run()
		}()
		handshakeChan <- struct{}{}
		// don't EXPECT any calls to sessionRunner.onHandshakeComplete()
		// make sure the go routine returns
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		streamManager.EXPECT().CloseWithError(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("calls the onHandshakeComplete callback when the handshake completes", func() {
		close(handshakeCompleteChan)
		sessionRunner.EXPECT().onHandshakeComplete(gomock.Any())
		go func() {
			defer GinkgoRecover()
			sess.run()
		}()
		Consistently(sess.Context().Done()).ShouldNot(BeClosed())
		// make sure the go routine returns
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		streamManager.EXPECT().CloseWithError(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("doesn't return a run error when closing", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			err := sess.run()
			Expect(err).ToNot(HaveOccurred())
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		Expect(sess.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("passes errors to the session runner", func() {
		testErr := errors.New("handshake error")
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			err := sess.run()
			Expect(err).To(MatchError(qerr.Error(0x1337, testErr.Error())))
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		Expect(sess.CloseWithError(0x1337, testErr)).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("process transport parameters received from the peer", func() {
		paramsChan := make(chan handshake.TransportParameters)
		sess.paramsChan = paramsChan
		go func() {
			defer GinkgoRecover()
			sess.run()
		}()
		params := handshake.TransportParameters{
			MaxStreams:                  123,
			IdleTimeout:                 90 * time.Second,
			StreamFlowControlWindow:     0x5000,
			ConnectionFlowControlWindow: 0x5000,
			OmitConnectionID:            true,
			MaxPacketSize:               0x42,
		}
		streamManager.EXPECT().UpdateLimits(&params)
		packer.EXPECT().HandleTransportParameters(&params)
		paramsChan <- params
		Eventually(func() *handshake.TransportParameters { return sess.peerParams }).Should(Equal(&params))
		// make the go routine return
		streamManager.EXPECT().CloseWithError(gomock.Any())
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		sess.Close()
		Eventually(sess.Context().Done()).Should(BeClosed())
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
			sent := make(chan struct{})
			packer.EXPECT().PackPacket().Do(func() (*packedPacket, error) {
				close(sent)
				return nil, nil
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess.run()
				close(done)
			}()
			Eventually(sent).Should(BeClosed())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(done).Should(BeClosed())
		})

		It("doesn't send a PING packet if keep-alive is disabled", func() {
			sess.handshakeComplete = true
			sess.config.KeepAlive = false
			sess.lastNetworkActivityTime = time.Now().Add(-remoteIdleTimeout / 2)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess.run()
				close(done)
			}()
			Consistently(mconn.written).ShouldNot(Receive())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(done).Should(BeClosed())
		})

		It("doesn't send a PING if the handshake isn't completed yet", func() {
			sess.handshakeComplete = false
			sess.config.KeepAlive = true
			sess.lastNetworkActivityTime = time.Now().Add(-remoteIdleTimeout / 2)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				sess.run()
				close(done)
			}()
			Consistently(mconn.written).ShouldNot(Receive())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sess.Close()
			Eventually(done).Should(BeClosed())
		})
	})

	Context("timeouts", func() {
		BeforeEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		It("times out due to no network activity", func() {
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.handshakeComplete = true
			sess.lastNetworkActivityTime = time.Now().Add(-time.Hour)
			done := make(chan struct{})
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
				return &packedPacket{}, nil
			})
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("times out due to non-completed handshake", func() {
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.sessionCreationTime = time.Now().Add(-protocol.DefaultHandshakeTimeout).Add(-time.Second)
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.ErrorCode).To(Equal(qerr.HandshakeTimeout))
				return &packedPacket{}, nil
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.HandshakeTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("does not use the idle timeout before the handshake complete", func() {
			sess.config.IdleTimeout = 9999 * time.Second
			defer sess.Close()
			sess.lastNetworkActivityTime = time.Now().Add(-time.Minute)
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.ErrorCode).To(Equal(qerr.PeerGoingAway))
				return &packedPacket{}, nil
			})
			// the handshake timeout is irrelevant here, since it depends on the time the session was created,
			// and not on the last network activity
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			Consistently(sess.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("closes the session due to the idle timeout after handshake", func() {
			sessionRunner.EXPECT().onHandshakeComplete(sess)
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
				return &packedPacket{}, nil
			})
			sess.config.IdleTimeout = 0
			close(handshakeCompleteChan)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				err := sess.run()
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.NetworkIdleTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
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
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(11)).Return(mstr, nil)
			str, err := sess.GetOrOpenStream(11)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("returns a nil-value (not an interface with value nil) for closed streams", func() {
			strI := Stream(nil)
			streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(1337)).Return(strI, nil)
			str, err := sess.GetOrOpenStream(1337)
			Expect(err).ToNot(HaveOccurred())
			// make sure that the returned value is a plain nil, not an Stream with value nil
			_, ok := str.(Stream)
			Expect(ok).To(BeFalse())
		})

		It("errors when trying to get a unidirectional stream", func() {
			streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(100)).Return(&sendStream{}, nil)
			_, err := sess.GetOrOpenStream(100)
			Expect(err).To(MatchError("Stream 100 is not a bidirectional stream"))
		})

		It("opens streams", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStream().Return(mstr, nil)
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens streams synchronously", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStreamSync().Return(mstr, nil)
			str, err := sess.OpenStreamSync()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens unidirectional streams", func() {
			mstr := NewMockSendStreamI(mockCtrl)
			streamManager.EXPECT().OpenUniStream().Return(mstr, nil)
			str, err := sess.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens unidirectional streams synchronously", func() {
			mstr := NewMockSendStreamI(mockCtrl)
			streamManager.EXPECT().OpenUniStreamSync().Return(mstr, nil)
			str, err := sess.OpenUniStreamSync()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts streams", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().AcceptStream().Return(mstr, nil)
			str, err := sess.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts unidirectional streams", func() {
			mstr := NewMockReceiveStreamI(mockCtrl)
			streamManager.EXPECT().AcceptUniStream().Return(mstr, nil)
			str, err := sess.AcceptUniStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
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

var _ = Describe("Client Session", func() {
	var (
		sess                  *session
		sessionRunner         *MockSessionRunner
		packer                *MockPacker
		mconn                 *mockConnection
		handshakeCompleteChan chan<- struct{}

		cryptoSetup *mockCryptoSetup
	)

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		cryptoSetup = &mockCryptoSetup{}
		newCryptoSetupClient = func(
			_ io.ReadWriter,
			_ protocol.ConnectionID,
			_ protocol.VersionNumber,
			_ *tls.Config,
			_ *handshake.TransportParameters,
			_ chan<- handshake.TransportParameters,
			_ chan<- struct{},
			handshakeCompleteChanP chan<- struct{},
			_ protocol.VersionNumber,
			_ []protocol.VersionNumber,
			_ utils.Logger,
		) (handshake.CryptoSetup, error) {
			handshakeCompleteChan = handshakeCompleteChanP
			return cryptoSetup, nil
		}

		mconn = newMockConnection()
		sessionRunner = NewMockSessionRunner(mockCtrl)
		sessP, err := newClientSession(
			mconn,
			sessionRunner,
			protocol.Version39,
			protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
			protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
			nil,
			populateClientConfig(&Config{}, false),
			protocol.VersionWhatever,
			nil,
			utils.DefaultLogger,
		)
		sess = sessP.(*session)
		Expect(err).ToNot(HaveOccurred())
		packer = NewMockPacker(mockCtrl)
		sess.packer = packer
	})

	AfterEach(func() {
		newCryptoSetupClient = handshake.NewCryptoSetupClient
	})

	It("sends a forward-secure packet when the handshake completes", func() {
		done := make(chan struct{})
		gomock.InOrder(
			sessionRunner.EXPECT().onHandshakeComplete(gomock.Any()),
			packer.EXPECT().PackPacket().DoAndReturn(func() (*packedPacket, error) {
				close(done)
				return &packedPacket{header: &wire.Header{}, raw: *getPacketBuffer()}, nil
			}),
			packer.EXPECT().PackPacket().AnyTimes(),
		)
		close(handshakeCompleteChan)
		go func() {
			defer GinkgoRecover()
			sess.run()
		}()
		Eventually(done).Should(BeClosed())
		//make sure the go routine returns
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("changes the connection ID when receiving the first packet from the server", func() {
		sess.version = protocol.VersionTLS
		unpacker := NewMockUnpacker(mockCtrl)
		unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
		sess.unpacker = unpacker
		go func() {
			defer GinkgoRecover()
			sess.run()
		}()
		newConnID := protocol.ConnectionID{1, 3, 3, 7, 1, 3, 3, 7}
		packer.EXPECT().ChangeDestConnectionID(newConnID)
		err := sess.handlePacketImpl(&receivedPacket{
			header: &wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  newConnID,
				DestConnectionID: sess.srcConnID,
			},
			data: []byte{0},
		})
		Expect(err).ToNot(HaveOccurred())
		// make sure the go routine returns
		sess.version = protocol.Version39
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		sessionRunner.EXPECT().removeConnectionID(gomock.Any())
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("doesn't retransmit an Initial packet if it already received a response", func() {
		unpacker := NewMockUnpacker(mockCtrl)
		unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
		sess.unpacker = unpacker
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sph.EXPECT().GetPacketNumberLen(gomock.Any()).Return(protocol.PacketNumberLen2).AnyTimes()
		sph.EXPECT().DequeuePacketForRetransmission().Return(&ackhandler.Packet{
			PacketNumber: 10,
			PacketType:   protocol.PacketTypeInitial,
		})
		sph.EXPECT().DequeuePacketForRetransmission()
		rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
		rph.EXPECT().ReceivedPacket(gomock.Any(), gomock.Any(), gomock.Any())
		sess.receivedPacketHandler = rph
		sess.sentPacketHandler = sph
		err := sess.handlePacketImpl(&receivedPacket{
			header: &wire.Header{},
			data:   []byte{0},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(sess.receivedFirstPacket).To(BeTrue())
		sent, err := sess.maybeSendRetransmission()
		Expect(err).NotTo(HaveOccurred())
		Expect(sent).To(BeFalse())
	})

	Context("receiving packets", func() {
		var hdr *wire.Header

		BeforeEach(func() {
			hdr = &wire.Header{PacketNumberLen: protocol.PacketNumberLen6}
		})

		It("passes the diversification nonce to the crypto setup", func() {
			cryptoSetup := &mockCryptoSetup{}
			sess.cryptoStreamHandler = cryptoSetup
			unpacker := NewMockUnpacker(mockCtrl)
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{}, nil)
			sess.unpacker = unpacker
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
			hdr.PacketNumber = 5
			hdr.DiversificationNonce = []byte("foobar")
			err := sess.handlePacketImpl(&receivedPacket{header: hdr})
			Expect(err).ToNot(HaveOccurred())
			Expect(cryptoSetup.divNonce).To(Equal(hdr.DiversificationNonce))
			// make the go routine return
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			sessionRunner.EXPECT().removeConnectionID(gomock.Any())
			Expect(sess.Close()).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})
	})
})
