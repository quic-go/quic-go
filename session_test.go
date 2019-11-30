package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime/pprof"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	mockackhandler "github.com/lucas-clemente/quic-go/internal/mocks/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/testutils"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
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

func areSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*session).run")
}

func areClosedSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*closedLocalSession).run")
}

var _ = Describe("Session", func() {
	var (
		sess          *session
		sessionRunner *MockSessionRunner
		mconn         *mockConnection
		streamManager *MockStreamManager
		packer        *MockPacker
		cryptoSetup   *mocks.MockCryptoSetup
	)
	srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	destConnID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
	clientDestConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	getPacket := func(pn protocol.PacketNumber) *packedPacket {
		buffer := getPacketBuffer()
		data := buffer.Slice[:0]
		data = append(data, []byte("foobar")...)
		return &packedPacket{
			raw:    data,
			buffer: buffer,
			header: &wire.ExtendedHeader{PacketNumber: pn},
		}
	}

	expectReplaceWithClosed := func() {
		sessionRunner.EXPECT().ReplaceWithClosed(clientDestConnID, gomock.Any()).MaxTimes(1)
		sessionRunner.EXPECT().ReplaceWithClosed(srcConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
			Expect(s).To(BeAssignableToTypeOf(&closedLocalSession{}))
			Expect(s.Close()).To(Succeed())
			Eventually(areClosedSessionsRunning).Should(BeFalse())
		})
	}

	BeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		sessionRunner = NewMockSessionRunner(mockCtrl)
		mconn = newMockConnection()
		tokenGenerator, err := handshake.NewTokenGenerator()
		Expect(err).ToNot(HaveOccurred())
		sess = newSession(
			mconn,
			sessionRunner,
			nil,
			clientDestConnID,
			destConnID,
			srcConnID,
			[16]byte{},
			populateServerConfig(&Config{}),
			nil, // tls.Config
			tokenGenerator,
			utils.DefaultLogger,
			protocol.VersionTLS,
		).(*session)
		streamManager = NewMockStreamManager(mockCtrl)
		sess.streamsMap = streamManager
		packer = NewMockPacker(mockCtrl)
		sess.packer = packer
		cryptoSetup = mocks.NewMockCryptoSetup(mockCtrl)
		sess.cryptoStreamHandler = cryptoSetup
	})

	AfterEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())
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
				Expect(sess.handleStreamFrame(f)).To(Succeed())
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
				Expect(sess.handleStreamFrame(f)).To(MatchError(testErr))
			})

			It("ignores STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(nil, nil) // for closed streams, the streamManager returns nil
				Expect(sess.handleStreamFrame(&wire.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar"),
				})).To(Succeed())
			})
		})

		Context("handling ACK frames", func() {
			It("informs the SentPacketHandler about ACKs", func() {
				f := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}}
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().ReceivedAck(f, protocol.PacketNumber(42), protocol.EncryptionHandshake, gomock.Any())
				sess.sentPacketHandler = sph
				err := sess.handleAckFrame(f, 42, protocol.EncryptionHandshake)
				Expect(err).ToNot(HaveOccurred())
			})

			It("tells the ReceivedPacketHandler to ignore low ranges", func() {
				cryptoSetup.EXPECT().SetLargest1RTTAcked(protocol.PacketNumber(3))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}}
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().ReceivedAck(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				sph.EXPECT().GetLowestPacketNotConfirmedAcked().Return(protocol.PacketNumber(0x42))
				sess.sentPacketHandler = sph
				rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
				rph.EXPECT().IgnoreBelow(protocol.PacketNumber(0x42))
				sess.receivedPacketHandler = rph
				Expect(sess.handleAckFrame(ack, 0, protocol.Encryption1RTT)).To(Succeed())
			})
		})

		Context("handling RESET_STREAM frames", func() {
			It("closes the streams for writing", func() {
				f := &wire.ResetStreamFrame{
					StreamID:   555,
					ErrorCode:  42,
					ByteOffset: 0x1337,
				}
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(555)).Return(str, nil)
				str.EXPECT().handleResetStreamFrame(f)
				err := sess.handleResetStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				f := &wire.ResetStreamFrame{
					StreamID:   7,
					ByteOffset: 0x1337,
				}
				testErr := errors.New("flow control violation")
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(7)).Return(str, nil)
				str.EXPECT().handleResetStreamFrame(f).Return(testErr)
				err := sess.handleResetStreamFrame(f)
				Expect(err).To(MatchError(testErr))
			})

			It("ignores RESET_STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(3)).Return(nil, nil)
				Expect(sess.handleFrame(&wire.ResetStreamFrame{
					StreamID:  3,
					ErrorCode: 42,
				}, 0, protocol.EncryptionUnspecified)).To(Succeed())
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
				Expect(sess.handleFrame(&wire.MaxStreamDataFrame{
					StreamID:   10,
					ByteOffset: 1337,
				}, 0, protocol.EncryptionUnspecified)).To(Succeed())
			})
		})

		Context("handling MAX_STREAM_ID frames", func() {
			It("passes the frame to the streamsMap", func() {
				f := &wire.MaxStreamsFrame{
					Type:         protocol.StreamTypeUni,
					MaxStreamNum: 10,
				}
				streamManager.EXPECT().HandleMaxStreamsFrame(f)
				err := sess.handleMaxStreamsFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				f := &wire.MaxStreamsFrame{MaxStreamNum: 10}
				testErr := errors.New("test error")
				streamManager.EXPECT().HandleMaxStreamsFrame(f).Return(testErr)
				err := sess.handleMaxStreamsFrame(f)
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

			It("ignores STOP_SENDING frames for a closed stream", func() {
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(3)).Return(nil, nil)
				Expect(sess.handleFrame(&wire.StopSendingFrame{
					StreamID:  3,
					ErrorCode: 1337,
				}, 0, protocol.EncryptionUnspecified)).To(Succeed())
			})
		})

		It("handles NEW_CONNECTION_ID frames", func() {
			Expect(sess.handleFrame(&wire.NewConnectionIDFrame{
				SequenceNumber: 10,
				ConnectionID:   protocol.ConnectionID{1, 2, 3, 4},
			}, 1, protocol.Encryption1RTT)).To(Succeed())
			Expect(sess.connIDManager.queue.Back().Value.ConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))
		})

		It("handles PING frames", func() {
			err := sess.handleFrame(&wire.PingFrame{}, 0, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects PATH_RESPONSE frames", func() {
			err := sess.handleFrame(&wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, 0, protocol.EncryptionUnspecified)
			Expect(err).To(MatchError("unexpected PATH_RESPONSE frame"))
		})

		It("handles PATH_CHALLENGE frames", func() {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			err := sess.handleFrame(&wire.PathChallengeFrame{Data: data}, 0, protocol.EncryptionUnspecified)
			Expect(err).ToNot(HaveOccurred())
			frames, _ := sess.framer.AppendControlFrames(nil, 1000)
			Expect(frames).To(Equal([]ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: data}}}))
		})

		It("rejects NEW_TOKEN frames", func() {
			err := sess.handleNewTokenFrame(&wire.NewTokenFrame{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ProtocolViolation))
		})

		It("handles BLOCKED frames", func() {
			err := sess.handleFrame(&wire.DataBlockedFrame{}, 0, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAM_BLOCKED frames", func() {
			err := sess.handleFrame(&wire.StreamDataBlockedFrame{}, 0, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAM_ID_BLOCKED frames", func() {
			err := sess.handleFrame(&wire.StreamsBlockedFrame{}, 0, protocol.EncryptionUnspecified)
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles CONNECTION_CLOSE frames, with a transport error code", func() {
			testErr := qerr.Error(qerr.StreamLimitError, "foobar")
			streamManager.EXPECT().CloseWithError(testErr)
			sessionRunner.EXPECT().ReplaceWithClosed(srcConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedRemoteSession{}))
			})
			sessionRunner.EXPECT().ReplaceWithClosed(clientDestConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedRemoteSession{}))
			})
			cryptoSetup.EXPECT().Close()

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				Expect(sess.run()).To(MatchError(testErr))
			}()
			ccf := &wire.ConnectionCloseFrame{
				ErrorCode:    qerr.StreamLimitError,
				ReasonPhrase: "foobar",
			}
			Expect(sess.handleFrame(ccf, 0, protocol.EncryptionUnspecified)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("handles CONNECTION_CLOSE frames, with an application error code", func() {
			testErr := qerr.ApplicationError(0x1337, "foobar")
			streamManager.EXPECT().CloseWithError(testErr)
			sessionRunner.EXPECT().ReplaceWithClosed(srcConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedRemoteSession{}))
			})
			sessionRunner.EXPECT().ReplaceWithClosed(clientDestConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedRemoteSession{}))
			})
			cryptoSetup.EXPECT().Close()

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				Expect(sess.run()).To(MatchError(testErr))
			}()
			ccf := &wire.ConnectionCloseFrame{
				ErrorCode:          0x1337,
				ReasonPhrase:       "foobar",
				IsApplicationError: true,
			}
			Expect(sess.handleFrame(ccf, 0, protocol.EncryptionUnspecified)).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})
	})

	It("tells its versions", func() {
		sess.version = 4242
		Expect(sess.GetVersion()).To(Equal(protocol.VersionNumber(4242)))
	})

	Context("closing", func() {
		var (
			runErr         error
			expectedRunErr error
		)

		BeforeEach(func() {
			Eventually(areSessionsRunning).Should(BeFalse())
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				runErr = sess.run()
			}()
			Eventually(areSessionsRunning).Should(BeTrue())
			expectedRunErr = nil
		})

		AfterEach(func() {
			if expectedRunErr != nil {
				Expect(runErr).To(MatchError(expectedRunErr))
			}
		})

		It("shuts down without error", func() {
			sess.handshakeComplete = true
			streamManager.EXPECT().CloseWithError(qerr.ApplicationError(0, ""))
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.IsApplicationError).To(BeTrue())
				Expect(f.ErrorCode).To(Equal(qerr.NoError))
				Expect(f.FrameType).To(BeZero())
				Expect(f.ReasonPhrase).To(BeEmpty())
				return &packedPacket{raw: []byte("connection close")}, nil
			})
			Expect(sess.Close()).To(Succeed())
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(mconn.written).To(Receive(ContainSubstring("connection close")))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("only closes once", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			Expect(sess.Close()).To(Succeed())
			Expect(sess.Close()).To(Succeed())
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(HaveLen(1))
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes with an error", func() {
			sess.handshakeComplete = true
			streamManager.EXPECT().CloseWithError(qerr.ApplicationError(0x1337, "test error"))
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.IsApplicationError).To(BeTrue())
				Expect(f.ErrorCode).To(BeEquivalentTo(0x1337))
				Expect(f.ReasonPhrase).To(Equal("test error"))
				return &packedPacket{}, nil
			})
			sess.CloseWithError(0x1337, "test error")
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("includes the frame type in transport-level close frames", func() {
			sess.handshakeComplete = true
			testErr := qerr.ErrorWithFrameType(0x1337, 0x42, "test error")
			streamManager.EXPECT().CloseWithError(testErr)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.IsApplicationError).To(BeFalse())
				Expect(f.FrameType).To(BeEquivalentTo(0x42))
				Expect(f.ErrorCode).To(BeEquivalentTo(0x1337))
				Expect(f.ReasonPhrase).To(Equal("test error"))
				return &packedPacket{}, nil
			})
			sess.closeLocal(testErr)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("doesn't send application-level error before the handshake completes", func() {
			streamManager.EXPECT().CloseWithError(qerr.ApplicationError(0x1337, "test error"))
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.IsApplicationError).To(BeFalse())
				Expect(f.ErrorCode).To(BeEquivalentTo(0x15a))
				Expect(f.ReasonPhrase).To(BeEmpty())
				return &packedPacket{}, nil
			})
			sess.CloseWithError(0x1337, "test error")
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(sess.Context().Done()).To(BeClosed())
		})

		It("closes the session in order to recreate it", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			sessionRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			sess.closeForRecreating()
			Expect(mconn.written).To(BeEmpty()) // no CONNECTION_CLOSE or PUBLIC_RESET sent
			Eventually(areSessionsRunning).Should(BeFalse())
			expectedRunErr = errCloseForRecreating
		})

		It("destroys the session", func() {
			testErr := errors.New("close")
			streamManager.EXPECT().CloseWithError(gomock.Any())
			sessionRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			sess.destroy(testErr)
			Eventually(areSessionsRunning).Should(BeFalse())
			Expect(mconn.written).To(BeEmpty()) // no CONNECTION_CLOSE or PUBLIC_RESET sent
			expectedRunErr = testErr
		})

		It("cancels the context when the run loop exists", func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
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
		var unpacker *MockUnpacker

		BeforeEach(func() {
			unpacker = NewMockUnpacker(mockCtrl)
			sess.unpacker = unpacker
		})

		getPacket := func(extHdr *wire.ExtendedHeader, data []byte) *receivedPacket {
			buf := &bytes.Buffer{}
			Expect(extHdr.Write(buf, sess.version)).To(Succeed())
			return &receivedPacket{
				data:   append(buf.Bytes(), data...),
				buffer: getPacketBuffer(),
			}
		}

		It("drops Retry packets", func() {
			hdr := wire.Header{
				IsLongHeader: true,
				Type:         protocol.PacketTypeRetry,
			}
			Expect(sess.handlePacketImpl(getPacket(&wire.ExtendedHeader{Header: hdr}, nil))).To(BeFalse())
		})

		It("informs the ReceivedPacketHandler about non-ack-eliciting packets", func() {
			hdr := &wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumber:    0x37,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			rcvTime := time.Now().Add(-10 * time.Second)
			unpacker.EXPECT().Unpack(gomock.Any(), rcvTime, gomock.Any()).Return(&unpackedPacket{
				packetNumber:    0x1337,
				encryptionLevel: protocol.EncryptionInitial,
				hdr:             hdr,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.EncryptionInitial, rcvTime, false)
			sess.receivedPacketHandler = rph
			packet := getPacket(hdr, nil)
			packet.rcvTime = rcvTime
			Expect(sess.handlePacketImpl(packet)).To(BeTrue())
		})

		It("informs the ReceivedPacketHandler about ack-eliciting packets", func() {
			hdr := &wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumber:    0x37,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			rcvTime := time.Now().Add(-10 * time.Second)
			buf := &bytes.Buffer{}
			Expect((&wire.PingFrame{}).Write(buf, sess.version)).To(Succeed())
			unpacker.EXPECT().Unpack(gomock.Any(), rcvTime, gomock.Any()).Return(&unpackedPacket{
				packetNumber:    0x1337,
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             hdr,
				data:            buf.Bytes(),
			}, nil)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.Encryption1RTT, rcvTime, true)
			sess.receivedPacketHandler = rph
			packet := getPacket(hdr, nil)
			packet.rcvTime = rcvTime
			Expect(sess.handlePacketImpl(packet)).To(BeTrue())
		})

		It("drops a packet when unpacking fails", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, handshake.ErrDecryptionFailed)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			expectReplaceWithClosed()
			sess.handlePacket(getPacket(&wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumberLen: protocol.PacketNumberLen1,
			}, nil))
			Consistently(sess.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			sess.closeLocal(errors.New("close"))
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("closes the session when unpacking fails because the reserved bits were incorrect", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, wire.ErrInvalidReservedBits)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				Expect(err).To(HaveOccurred())
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ProtocolViolation))
				close(done)
			}()
			expectReplaceWithClosed()
			sess.handlePacket(getPacket(&wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumberLen: protocol.PacketNumberLen1,
			}, nil))
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("ignores packets when unpacking fails for any other reason", func() {
			testErr := errors.New("test err")
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, testErr)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			runErr := make(chan error)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				runErr <- sess.run()
			}()
			expectReplaceWithClosed()
			sess.handlePacket(getPacket(&wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumberLen: protocol.PacketNumberLen1,
			}, nil))
			Consistently(runErr).ShouldNot(Receive())
			// make the go routine return
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("rejects packets with empty payload", func() {
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{
				hdr:  &wire.ExtendedHeader{},
				data: []byte{}, // no payload
			}, nil)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				Expect(err).To(MatchError("PROTOCOL_VIOLATION: empty packet"))
				close(done)
			}()
			expectReplaceWithClosed()
			sess.handlePacket(getPacket(&wire.ExtendedHeader{
				Header:          wire.Header{DestConnectionID: srcConnID},
				PacketNumberLen: protocol.PacketNumberLen1,
			}, nil))
			Eventually(done).Should(BeClosed())
		})

		It("ignores 0-RTT packets", func() {
			hdr := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketType0RTT,
					DestConnectionID: srcConnID,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			Expect(sess.handlePacketImpl(getPacket(hdr, nil))).To(BeFalse())
		})

		It("ignores packets with a different source connection ID", func() {
			hdr1 := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          sess.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			hdr2 := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: destConnID,
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
					Length:           1,
					Version:          sess.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    2,
			}
			Expect(srcConnID).ToNot(Equal(hdr2.SrcConnectionID))
			// Send one packet, which might change the connection ID.
			// only EXPECT one call to the unpacker
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             hdr1,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			Expect(sess.handlePacketImpl(getPacket(hdr1, nil))).To(BeTrue())
			// The next packet has to be ignored, since the source connection ID doesn't match.
			Expect(sess.handlePacketImpl(getPacket(hdr2, nil))).To(BeFalse())
		})

		It("queues undecryptable packets", func() {
			hdr := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          sess.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable)
			packet := getPacket(hdr, nil)
			Expect(sess.handlePacketImpl(packet)).To(BeFalse())
			Expect(sess.undecryptablePackets).To(Equal([]*receivedPacket{packet}))
		})

		Context("updating the remote address", func() {
			It("doesn't support connection migration", func() {
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{
					encryptionLevel: protocol.Encryption1RTT,
					hdr:             &wire.ExtendedHeader{},
					data:            []byte{0}, // one PADDING frame
				}, nil)
				origAddr := sess.conn.(*mockConnection).remoteAddr
				remoteIP := &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				Expect(origAddr).ToNot(Equal(remoteIP))
				packet := getPacket(&wire.ExtendedHeader{
					Header:          wire.Header{DestConnectionID: srcConnID},
					PacketNumberLen: protocol.PacketNumberLen1,
				}, nil)
				packet.remoteAddr = remoteIP
				Expect(sess.handlePacketImpl(packet)).To(BeTrue())
				Expect(sess.conn.(*mockConnection).remoteAddr).To(Equal(origAddr))
			})
		})

		Context("coalesced packets", func() {
			getPacketWithLength := func(connID protocol.ConnectionID, length protocol.ByteCount) (int /* header length */, *receivedPacket) {
				hdr := &wire.ExtendedHeader{
					Header: wire.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: connID,
						SrcConnectionID:  destConnID,
						Version:          protocol.VersionTLS,
						Length:           length,
					},
					PacketNumberLen: protocol.PacketNumberLen3,
				}
				hdrLen := hdr.GetLength(sess.version)
				b := make([]byte, 1)
				rand.Read(b)
				packet := getPacket(hdr, bytes.Repeat(b, int(length)-3))
				return int(hdrLen), packet
			}

			It("cuts packets to the right length", func() {
				hdrLen, packet := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
					}, nil
				})
				Expect(sess.handlePacketImpl(packet)).To(BeTrue())
			})

			It("handles coalesced packets", func() {
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen1 + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
					}, nil
				})
				hdrLen2, packet2 := getPacketWithLength(srcConnID, 123)
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen2 + 123 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
					}, nil
				})
				packet1.data = append(packet1.data, packet2.data...)
				Expect(sess.handlePacketImpl(packet1)).To(BeTrue())
			})

			It("works with undecryptable packets", func() {
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				hdrLen2, packet2 := getPacketWithLength(srcConnID, 123)
				gomock.InOrder(
					unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable),
					unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
						Expect(data).To(HaveLen(hdrLen2 + 123 - 3))
						return &unpackedPacket{
							encryptionLevel: protocol.EncryptionHandshake,
							data:            []byte{0},
						}, nil
					}),
				)
				packet1.data = append(packet1.data, packet2.data...)
				Expect(sess.handlePacketImpl(packet1)).To(BeTrue())

				Expect(sess.undecryptablePackets).To(HaveLen(1))
				Expect(sess.undecryptablePackets[0].data).To(HaveLen(hdrLen1 + 456 - 3))
			})

			It("ignores coalesced packet parts if the destination connection IDs don't match", func() {
				wrongConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
				Expect(srcConnID).ToNot(Equal(wrongConnID))
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen1 + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
					}, nil
				})
				_, packet2 := getPacketWithLength(wrongConnID, 123)
				// don't EXPECT any calls to unpacker.Unpack()
				packet1.data = append(packet1.data, packet2.data...)
				Expect(sess.handlePacketImpl(packet1)).To(BeTrue())
			})
		})
	})

	Context("sending packets", func() {
		BeforeEach(func() {
			cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
			go func() {
				defer GinkgoRecover()
				sess.run()
			}()
		})

		AfterEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sends packets", func() {
			packer.EXPECT().PackPacket().Return(getPacket(1), nil)
			sess.receivedPacketHandler.ReceivedPacket(0x035e, protocol.Encryption1RTT, time.Now(), true)
			sent, err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
			Eventually(mconn.written).Should(Receive())
		})

		It("doesn't send packets if there's nothing to send", func() {
			packer.EXPECT().PackPacket().Return(getPacket(2), nil)
			sess.receivedPacketHandler.ReceivedPacket(0x035e, protocol.Encryption1RTT, time.Now(), true)
			sent, err := sess.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(sent).To(BeTrue())
		})

		It("sends ACK only packets", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
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
			Expect(frames).To(Equal([]ackhandler.Frame{{Frame: &wire.DataBlockedFrame{DataLimit: 1337}}}))
		})

		It("doesn't send when the SentPacketHandler doesn't allow it", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode().Return(ackhandler.SendNone)
			sess.sentPacketHandler = sph
			err := sess.sendPackets()
			Expect(err).ToNot(HaveOccurred())
		})

		for _, enc := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
			encLevel := enc

			Context(fmt.Sprintf("sending %s probe packets", encLevel), func() {
				var sendMode ackhandler.SendMode
				var getFrame func(protocol.ByteCount) wire.Frame

				BeforeEach(func() {
					switch encLevel {
					case protocol.EncryptionInitial:
						sendMode = ackhandler.SendPTOInitial
						getFrame = sess.retransmissionQueue.GetInitialFrame
					case protocol.EncryptionHandshake:
						sendMode = ackhandler.SendPTOHandshake
						getFrame = sess.retransmissionQueue.GetHandshakeFrame
					case protocol.Encryption1RTT:
						sendMode = ackhandler.SendPTOAppData
						getFrame = sess.retransmissionQueue.GetAppDataFrame
					}
				})

				It("sends a probe packet", func() {
					sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
					sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
					sph.EXPECT().TimeUntilSend()
					sph.EXPECT().SendMode().Return(sendMode)
					sph.EXPECT().ShouldSendNumPackets().Return(1)
					sph.EXPECT().QueueProbePacket(encLevel)
					packer.EXPECT().MaybePackProbePacket(encLevel).Return(getPacket(123), nil)
					sph.EXPECT().SentPacket(gomock.Any()).Do(func(packet *ackhandler.Packet) {
						Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(123)))
					})
					sess.sentPacketHandler = sph
					Expect(sess.sendPackets()).To(Succeed())
				})

				It("sends a PING as a probe packet", func() {
					sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
					sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
					sph.EXPECT().TimeUntilSend()
					sph.EXPECT().SendMode().Return(sendMode)
					sph.EXPECT().ShouldSendNumPackets().Return(1)
					sph.EXPECT().QueueProbePacket(encLevel).Return(false)
					packer.EXPECT().MaybePackProbePacket(encLevel).Return(getPacket(123), nil)
					sph.EXPECT().SentPacket(gomock.Any()).Do(func(packet *ackhandler.Packet) {
						Expect(packet.PacketNumber).To(Equal(protocol.PacketNumber(123)))
					})
					sess.sentPacketHandler = sph
					Expect(sess.sendPackets()).To(Succeed())
					// We're using a mock packet packer in this test.
					// We therefore need to test separately that the PING was actually queued.
					Expect(getFrame(1000)).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				})
			})
		}
	})

	Context("packet pacing", func() {
		var sph *mockackhandler.MockSentPacketHandler

		BeforeEach(func() {
			sph = mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sess.sentPacketHandler = sph
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		AfterEach(func() {
			// make the go routine return
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			Expect(sess.Close()).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sends multiple packets one by one immediately", func() {
			sph.EXPECT().SentPacket(gomock.Any()).Times(2)
			sph.EXPECT().ShouldSendNumPackets().Return(1).Times(2)
			sph.EXPECT().TimeUntilSend().Return(time.Now()).Times(2)
			sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
			sph.EXPECT().SendMode().Return(ackhandler.SendAny).Times(2) // allow 2 packets...
			packer.EXPECT().PackPacket().Return(getPacket(10), nil)
			packer.EXPECT().PackPacket().Return(getPacket(11), nil)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			sess.scheduleSending()
			Eventually(mconn.written).Should(HaveLen(2))
			Consistently(mconn.written).Should(HaveLen(2))
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
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			sess.scheduleSending()
			Eventually(mconn.written).Should(HaveLen(1))
			Consistently(mconn.written).Should(HaveLen(1))
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
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			sess.scheduleSending()
			Eventually(mconn.written).Should(HaveLen(1))
			Consistently(mconn.written, pacingDelay/2).Should(HaveLen(1))
			Eventually(mconn.written, 2*pacingDelay).Should(HaveLen(2))
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
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			sess.scheduleSending()
			Eventually(mconn.written).Should(HaveLen(3))
		})

		It("doesn't set a pacing timer when there is no data to send", func() {
			sph.EXPECT().TimeUntilSend().Return(time.Now())
			sph.EXPECT().ShouldSendNumPackets().Return(1)
			sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
			packer.EXPECT().PackPacket()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			sess.scheduleSending() // no packet will get sent
			Consistently(mconn.written).ShouldNot(Receive())
		})
	})

	Context("scheduling sending", func() {
		It("sends when scheduleSending is called", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().TimeUntilSend().AnyTimes()
			sph.EXPECT().SendMode().Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().ShouldSendNumPackets().AnyTimes().Return(1)
			sph.EXPECT().SentPacket(gomock.Any())
			sess.sentPacketHandler = sph
			packer.EXPECT().PackPacket().Return(getPacket(1), nil)

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			Consistently(mconn.written).ShouldNot(Receive())
			sess.scheduleSending()
			Eventually(mconn.written).Should(Receive())
			// make the go routine return
			expectReplaceWithClosed()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sets the timer to the ack timer", func() {
			packer.EXPECT().PackPacket().Return(getPacket(1234), nil)
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().TimeUntilSend().Return(time.Now())
			sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
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
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			Eventually(mconn.written).Should(Receive())
			// make sure the go routine returns
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			expectReplaceWithClosed()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})
	})

	It("cancels the HandshakeComplete context and informs the SentPacketHandler when the handshake completes", func() {
		packer.EXPECT().PackPacket().AnyTimes()
		finishHandshake := make(chan struct{})
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sess.sentPacketHandler = sph
		sphNotified := make(chan struct{})
		sph.EXPECT().SetHandshakeComplete().Do(func() { close(sphNotified) })
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SendMode().AnyTimes()
		sessionRunner.EXPECT().Retire(clientDestConnID)
		go func() {
			defer GinkgoRecover()
			<-finishHandshake
			cryptoSetup.EXPECT().RunHandshake()
			close(sess.handshakeCompleteChan)
			sess.run()
		}()
		handshakeCtx := sess.HandshakeComplete()
		Consistently(handshakeCtx.Done()).ShouldNot(BeClosed())
		close(finishHandshake)
		Eventually(handshakeCtx.Done()).Should(BeClosed())
		Eventually(sphNotified).Should(BeClosed())
		// make sure the go routine returns
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.EXPECT().Close()
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("doesn't cancel the HandshakeComplete context when the handshake fails", func() {
		packer.EXPECT().PackPacket().AnyTimes()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.EXPECT().Close()
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().RunHandshake()
			sess.run()
		}()
		handshakeCtx := sess.HandshakeComplete()
		Consistently(handshakeCtx.Done()).ShouldNot(BeClosed())
		sess.closeLocal(errors.New("handshake error"))
		Consistently(handshakeCtx.Done()).ShouldNot(BeClosed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("sends a 1-RTT packet when the handshake completes", func() {
		done := make(chan struct{})
		sessionRunner.EXPECT().Retire(clientDestConnID)
		packer.EXPECT().PackPacket().DoAndReturn(func() (*packedPacket, error) {
			defer close(done)
			return &packedPacket{
				header: &wire.ExtendedHeader{},
				buffer: getPacketBuffer(),
			}, nil
		})
		packer.EXPECT().PackPacket().AnyTimes()
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().RunHandshake()
			close(sess.handshakeCompleteChan)
			sess.run()
		}()
		Eventually(done).Should(BeClosed())
		// make sure the go routine returns
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.EXPECT().Close()
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("doesn't return a run error when closing", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
			Expect(sess.run()).To(Succeed())
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.EXPECT().Close()
		Expect(sess.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("passes errors to the session runner", func() {
		testErr := errors.New("handshake error")
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
			err := sess.run()
			Expect(err).To(MatchError(qerr.ApplicationError(0x1337, testErr.Error())))
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		cryptoSetup.EXPECT().Close()
		Expect(sess.CloseWithError(0x1337, testErr.Error())).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	Context("transport parameters", func() {
		It("errors if it can't unmarshal the TransportParameters", func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("transport parameter"))
			}()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			expectReplaceWithClosed()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			sess.processTransportParameters([]byte("invalid"))
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("processes transport parameters received from the client", func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			params := &handshake.TransportParameters{
				IdleTimeout:                   90 * time.Second,
				InitialMaxStreamDataBidiLocal: 0x5000,
				InitialMaxData:                0x5000,
				ActiveConnectionIDLimit:       3,
				// marshaling always sets it to this value
				MaxPacketSize: protocol.MaxReceivePacketSize,
			}
			streamManager.EXPECT().UpdateLimits(params)
			packer.EXPECT().HandleTransportParameters(params)
			packer.EXPECT().PackPacket().MaxTimes(3)
			Expect(sess.earlySessionReady()).ToNot(BeClosed())
			sessionRunner.EXPECT().Add(gomock.Any(), sess).Times(3)
			sess.processTransportParameters(params.Marshal())
			Expect(sess.earlySessionReady()).To(BeClosed())

			// make the go routine return
			streamManager.EXPECT().CloseWithError(gomock.Any())

			sessionRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedLocalSession{}))
				Expect(s.Close()).To(Succeed())
			}).Times(5) // initial connection ID + initial client dest conn ID + 3 newly issued conn IDs
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})
	})

	Context("keep-alives", func() {
		setRemoteIdleTimeout := func(t time.Duration) {
			tp := &handshake.TransportParameters{IdleTimeout: t}
			streamManager.EXPECT().UpdateLimits(gomock.Any())
			packer.EXPECT().HandleTransportParameters(gomock.Any())
			sess.processTransportParameters(tp.Marshal())
		}

		runSession := func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
		}

		BeforeEach(func() {
			sess.config.KeepAlive = true
			sess.handshakeComplete = true
		})

		AfterEach(func() {
			// make the go routine return
			expectReplaceWithClosed()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			Expect(sess.Close()).To(Succeed())
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("sends a PING as a keep-alive after half the idle timeout", func() {
			setRemoteIdleTimeout(5 * time.Second)
			sess.lastPacketReceivedTime = time.Now().Add(-protocol.MaxKeepAliveInterval)
			sent := make(chan struct{})
			packer.EXPECT().PackPacket().Do(func() (*packedPacket, error) {
				close(sent)
				return nil, nil
			})
			runSession()
			Eventually(sent).Should(BeClosed())
		})

		It("sends a PING after a maximum of protocol.MaxKeepAliveInterval", func() {
			setRemoteIdleTimeout(time.Hour)
			sess.lastPacketReceivedTime = time.Now().Add(-protocol.MaxKeepAliveInterval).Add(-time.Millisecond)
			sent := make(chan struct{})
			packer.EXPECT().PackPacket().Do(func() (*packedPacket, error) {
				close(sent)
				return nil, nil
			})
			runSession()
			Eventually(sent).Should(BeClosed())
		})

		It("doesn't send a PING packet if keep-alive is disabled", func() {
			setRemoteIdleTimeout(5 * time.Second)
			sess.config.KeepAlive = false
			sess.lastPacketReceivedTime = time.Now().Add(-time.Second * 5 / 2)
			runSession()
			Consistently(mconn.written).ShouldNot(Receive())
		})

		It("doesn't send a PING if the handshake isn't completed yet", func() {
			sess.handshakeComplete = false
			// Needs to be shorter than our idle timeout.
			// Otherwise we'll try to send a CONNECTION_CLOSE.
			sess.lastPacketReceivedTime = time.Now().Add(-20 * time.Second)
			runSession()
			Consistently(mconn.written).ShouldNot(Receive())
		})
	})

	Context("timeouts", func() {
		BeforeEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		It("times out due to no network activity", func() {
			sessionRunner.EXPECT().Remove(gomock.Any()).Times(2)
			sess.handshakeComplete = true
			sess.lastPacketReceivedTime = time.Now().Add(-time.Hour)
			done := make(chan struct{})
			cryptoSetup.EXPECT().Close()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("No recent network activity"))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("times out due to non-completed handshake", func() {
			sess.sessionCreationTime = time.Now().Add(-protocol.DefaultHandshakeTimeout).Add(-time.Second)
			sessionRunner.EXPECT().Remove(gomock.Any()).Times(2)
			cryptoSetup.EXPECT().Close()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("Handshake did not complete in time"))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("does not use the idle timeout before the handshake complete", func() {
			sess.config.IdleTimeout = 9999 * time.Second
			sess.lastPacketReceivedTime = time.Now().Add(-time.Minute)
			packer.EXPECT().PackConnectionClose(gomock.Any()).DoAndReturn(func(f *wire.ConnectionCloseFrame) (*packedPacket, error) {
				Expect(f.ErrorCode).To(Equal(qerr.NoError))
				return &packedPacket{}, nil
			})
			// the handshake timeout is irrelevant here, since it depends on the time the session was created,
			// and not on the last network activity
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			Consistently(sess.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			sess.handshakeComplete = true
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("closes the session due to the idle timeout after handshake", func() {
			packer.EXPECT().PackPacket().AnyTimes()
			gomock.InOrder(
				sessionRunner.EXPECT().Retire(clientDestConnID),
				sessionRunner.EXPECT().Remove(gomock.Any()),
			)
			cryptoSetup.EXPECT().Close()
			sess.config.IdleTimeout = 0
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				close(sess.handshakeCompleteChan)
				err := sess.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err.Error()).To(ContainSubstring("No recent network activity"))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("doesn't time out when it just sent a packet", func() {
			sess.handshakeComplete = true
			sess.lastPacketReceivedTime = time.Now().Add(-time.Hour)
			sess.firstAckElicitingPacketAfterIdleSentTime = time.Now().Add(-time.Second)
			sess.config.IdleTimeout = 30 * time.Second
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			Consistently(sess.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
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
		It("opens streams", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStream().Return(mstr, nil)
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens streams synchronously", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStreamSync(context.Background()).Return(mstr, nil)
			str, err := sess.OpenStreamSync(context.Background())
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
			streamManager.EXPECT().OpenUniStreamSync(context.Background()).Return(mstr, nil)
			str, err := sess.OpenUniStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts streams", func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().AcceptStream(ctx).Return(mstr, nil)
			str, err := sess.AcceptStream(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts unidirectional streams", func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			mstr := NewMockReceiveStreamI(mockCtrl)
			streamManager.EXPECT().AcceptUniStream(ctx).Return(mstr, nil)
			str, err := sess.AcceptUniStream(ctx)
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
		sess          *session
		sessionRunner *MockSessionRunner
		packer        *MockPacker
		mconn         *mockConnection
		cryptoSetup   *mocks.MockCryptoSetup
		tlsConf       *tls.Config
		quicConf      *Config
	)
	srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
	destConnID := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}

	getPacket := func(hdr *wire.ExtendedHeader, data []byte) *receivedPacket {
		buf := &bytes.Buffer{}
		Expect(hdr.Write(buf, sess.version)).To(Succeed())
		return &receivedPacket{
			data:   append(buf.Bytes(), data...),
			buffer: getPacketBuffer(),
		}
	}

	expectReplaceWithClosed := func() {
		sessionRunner.EXPECT().ReplaceWithClosed(srcConnID, gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
			Expect(s.Close()).To(Succeed())
			Eventually(areClosedSessionsRunning).Should(BeFalse())
		})
	}

	BeforeEach(func() {
		quicConf = populateClientConfig(&Config{}, true)
	})

	JustBeforeEach(func() {
		Eventually(areSessionsRunning).Should(BeFalse())

		if tlsConf == nil {
			tlsConf = &tls.Config{}
		}
		mconn = newMockConnection()
		sessionRunner = NewMockSessionRunner(mockCtrl)
		sess = newClientSession(
			mconn,
			sessionRunner,
			destConnID,
			protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
			quicConf,
			tlsConf,
			42, // initial packet number
			protocol.VersionTLS,
			utils.DefaultLogger,
			protocol.VersionTLS,
		).(*session)
		packer = NewMockPacker(mockCtrl)
		sess.packer = packer
		cryptoSetup = mocks.NewMockCryptoSetup(mockCtrl)
		sess.cryptoStreamHandler = cryptoSetup
	})

	It("changes the connection ID when receiving the first packet from the server", func() {
		unpacker := NewMockUnpacker(mockCtrl)
		unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(hdr *wire.Header, _ time.Time, data []byte) (*unpackedPacket, error) {
			return &unpackedPacket{
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             &wire.ExtendedHeader{Header: *hdr},
				data:            []byte{0}, // one PADDING frame
			}, nil
		})
		sess.unpacker = unpacker
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
			sess.run()
		}()
		newConnID := protocol.ConnectionID{1, 3, 3, 7, 1, 3, 3, 7}
		Expect(sess.handlePacketImpl(getPacket(&wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  newConnID,
				DestConnectionID: srcConnID,
				Length:           1,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, []byte{0}))).To(BeTrue())
		// make sure the go routine returns
		packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
		expectReplaceWithClosed()
		cryptoSetup.EXPECT().Close()
		Expect(sess.Close()).To(Succeed())
		Eventually(sess.Context().Done()).Should(BeClosed())
	})

	It("continues accepting Long Header packets after using a new connection ID", func() {
		unpacker := NewMockUnpacker(mockCtrl)
		sess.unpacker = unpacker
		sessionRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any())
		sess.handleNewConnectionIDFrame(&wire.NewConnectionIDFrame{
			SequenceNumber: 1,
			ConnectionID:   protocol.ConnectionID{1, 2, 3, 4, 5},
		})
		Expect(sess.connIDManager.Get()).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5}))
		// now receive a packet with the original source connection ID
		unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(hdr *wire.Header, _ time.Time, _ []byte) (*unpackedPacket, error) {
			return &unpackedPacket{
				hdr:             &wire.ExtendedHeader{Header: *hdr},
				data:            []byte{0},
				encryptionLevel: protocol.EncryptionHandshake,
			}, nil
		})
		hdr := &wire.Header{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: srcConnID,
			SrcConnectionID:  destConnID,
		}
		Expect(sess.handleSinglePacket(&receivedPacket{buffer: getPacketBuffer()}, hdr)).To(BeTrue())
	})

	Context("handling tokens", func() {
		var mockTokenStore *MockTokenStore

		BeforeEach(func() {
			mockTokenStore = NewMockTokenStore(mockCtrl)
			tlsConf = &tls.Config{ServerName: "server"}
			quicConf.TokenStore = mockTokenStore
			mockTokenStore.EXPECT().Pop(gomock.Any())
			quicConf.TokenStore = mockTokenStore
		})

		It("handles NEW_TOKEN frames", func() {
			mockTokenStore.EXPECT().Put("server", &ClientToken{data: []byte("foobar")})
			Expect(sess.handleNewTokenFrame(&wire.NewTokenFrame{Token: []byte("foobar")})).To(Succeed())
		})
	})

	Context("handling Retry", func() {
		var validRetryHdr *wire.ExtendedHeader

		JustBeforeEach(func() {
			validRetryHdr = &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:         true,
					Type:                 protocol.PacketTypeRetry,
					SrcConnectionID:      protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
					DestConnectionID:     protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					OrigDestConnectionID: protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
					Token:                []byte("foobar"),
					Version:              sess.version,
				},
			}
		})

		It("handles Retry packets", func() {
			cryptoSetup.EXPECT().ChangeConnectionID(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef})
			packer.EXPECT().SetToken([]byte("foobar"))
			Expect(sess.handlePacketImpl(getPacket(validRetryHdr, nil))).To(BeTrue())
		})

		It("ignores Retry packets after receiving a regular packet", func() {
			sess.receivedFirstPacket = true
			Expect(sess.handlePacketImpl(getPacket(validRetryHdr, nil))).To(BeFalse())
		})

		It("ignores Retry packets if the server didn't change the connection ID", func() {
			validRetryHdr.SrcConnectionID = destConnID
			Expect(sess.handlePacketImpl(getPacket(validRetryHdr, nil))).To(BeFalse())
		})

		It("ignores Retry packets with the wrong original destination connection ID", func() {
			hdr := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:         true,
					Type:                 protocol.PacketTypeRetry,
					SrcConnectionID:      protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
					DestConnectionID:     protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					OrigDestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
					Token:                []byte("foobar"),
				},
				PacketNumberLen: protocol.PacketNumberLen3,
			}
			Expect(sess.handlePacketImpl(getPacket(hdr, nil))).To(BeFalse())
		})
	})

	Context("transport parameters", func() {
		It("errors if it can't unmarshal the TransportParameters", func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				err := sess.run()
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("transport parameter"))
			}()
			expectReplaceWithClosed()
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			sess.processTransportParameters([]byte("invalid"))
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("immediately retires the preferred_address connection ID", func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().RunHandshake().MaxTimes(1)
				sess.run()
			}()
			params := &handshake.TransportParameters{
				PreferredAddress: &handshake.PreferredAddress{
					IPv4:         net.IPv4(127, 0, 0, 1),
					IPv6:         net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					ConnectionID: protocol.ConnectionID{1, 2, 3, 4},
				},
			}
			packer.EXPECT().HandleTransportParameters(gomock.Any())
			packer.EXPECT().PackPacket().MaxTimes(1)
			sess.processTransportParameters(params.Marshal())
			cf, _ := sess.framer.AppendControlFrames(nil, protocol.MaxByteCount)
			Expect(cf).To(HaveLen(1))
			Expect(cf[0].Frame).To(Equal(&wire.RetireConnectionIDFrame{SequenceNumber: 1}))

			// make the go routine return
			sessionRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any()).Do(func(_ protocol.ConnectionID, s packetHandler) {
				Expect(s).To(BeAssignableToTypeOf(&closedLocalSession{}))
				Expect(s.Close()).To(Succeed())
			})
			packer.EXPECT().PackConnectionClose(gomock.Any()).Return(&packedPacket{}, nil)
			cryptoSetup.EXPECT().Close()
			sess.Close()
			Eventually(sess.Context().Done()).Should(BeClosed())
		})

		It("errors if the TransportParameters contain an original_connection_id, although no Retry was performed", func() {
			params := &handshake.TransportParameters{
				OriginalConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				StatelessResetToken:  &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			_, err := sess.processTransportParametersForClient(params.Marshal())
			Expect(err).To(MatchError("TRANSPORT_PARAMETER_ERROR: expected original_connection_id to equal (empty), is 0xdecafbad"))
		})

		It("errors if the TransportParameters contain a wrong original_connection_id", func() {
			sess.origDestConnID = protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			params := &handshake.TransportParameters{
				OriginalConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				StatelessResetToken:  &[16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			_, err := sess.processTransportParametersForClient(params.Marshal())
			Expect(err).To(MatchError("TRANSPORT_PARAMETER_ERROR: expected original_connection_id to equal 0xdeadbeef, is 0xdecafbad"))
		})
	})

	Context("handling potentially injected packets", func() {
		var unpacker *MockUnpacker

		getPacket := func(extHdr *wire.ExtendedHeader, data []byte) *receivedPacket {
			buf := &bytes.Buffer{}
			Expect(extHdr.Write(buf, sess.version)).To(Succeed())
			return &receivedPacket{
				data:   append(buf.Bytes(), data...),
				buffer: getPacketBuffer(),
			}
		}

		// Convert an already packed raw packet into a receivedPacket
		wrapPacket := func(packet []byte) *receivedPacket {
			return &receivedPacket{
				data:   packet,
				buffer: getPacketBuffer(),
			}
		}

		// Illustrates that attacker may inject an Initial packet with a different
		// source connection ID, causing endpoint to ignore a subsequent real Initial packets.
		It("ignores Initial packets with a different source connection ID", func() {
			// Modified from test "ignores packets with a different source connection ID"
			unpacker = NewMockUnpacker(mockCtrl)
			sess.unpacker = unpacker

			hdr1 := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          sess.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			hdr2 := &wire.ExtendedHeader{
				Header: wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
					Length:           1,
					Version:          sess.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    2,
			}
			Expect(hdr2.SrcConnectionID).ToNot(Equal(srcConnID))
			// Send one packet, which might change the connection ID.
			// only EXPECT one call to the unpacker
			unpacker.EXPECT().Unpack(gomock.Any(), gomock.Any(), gomock.Any()).Return(&unpackedPacket{
				encryptionLevel: protocol.EncryptionInitial,
				hdr:             hdr1,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			Expect(sess.handlePacketImpl(getPacket(hdr1, nil))).To(BeTrue())
			// The next packet has to be ignored, since the source connection ID doesn't match.
			Expect(sess.handlePacketImpl(getPacket(hdr2, nil))).To(BeFalse())
		})

		// Illustrates that an injected Initial with an ACK frame for an unsent packet causes
		// the connection to immediately break down
		It("fails on Initial-level ACK for unsent packet", func() {
			ackFrame := testutils.ComposeAckFrame(0, 0)
			initialPacket := testutils.ComposeInitialPacket(destConnID, srcConnID, sess.version, destConnID, []wire.Frame{ackFrame})
			Expect(sess.handlePacketImpl(wrapPacket(initialPacket))).To(BeFalse())
		})

		// Illustrates that an injected Initial with a CONNECTION_CLOSE frame causes
		// the connection to immediately break down
		It("fails on Initial-level CONNECTION_CLOSE frame", func() {
			connCloseFrame := testutils.ComposeConnCloseFrame()
			initialPacket := testutils.ComposeInitialPacket(destConnID, srcConnID, sess.version, destConnID, []wire.Frame{connCloseFrame})
			Expect(sess.handlePacketImpl(wrapPacket(initialPacket))).To(BeTrue())
		})

		// Illustrates that attacker who injects a Retry packet and changes the connection ID
		// can cause subsequent real Initial packets to be ignored
		It("ignores Initial packets which use original source id, after accepting a Retry", func() {
			newSrcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			cryptoSetup.EXPECT().ChangeConnectionID(newSrcConnID)
			packer.EXPECT().SetToken([]byte("foobar"))

			sess.handlePacketImpl(wrapPacket(testutils.ComposeRetryPacket(newSrcConnID, destConnID, destConnID, []byte("foobar"), sess.version)))
			initialPacket := testutils.ComposeInitialPacket(sess.connIDManager.Get(), srcConnID, sess.version, sess.connIDManager.Get(), nil)
			Expect(sess.handlePacketImpl(wrapPacket(initialPacket))).To(BeFalse())
		})

	})
})
