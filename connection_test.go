package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/testutils"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func areConnsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*connection).run")
}

var _ = Describe("Connection", func() {
	var (
		conn          *connection
		connRunner    *MockConnRunner
		mconn         *MockSendConn
		streamManager *MockStreamManager
		packer        *MockPacker
		cryptoSetup   *mocks.MockCryptoSetup
		tracer        *mocklogging.MockConnectionTracer
		capabilities  connCapabilities
	)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7331}
	srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	destConnID := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})
	clientDestConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

	getCoalescedPacket := func(pn protocol.PacketNumber, isLongHeader bool) *coalescedPacket {
		buffer := getPacketBuffer()
		buffer.Data = append(buffer.Data, []byte("foobar")...)
		packet := &coalescedPacket{buffer: buffer}
		if isLongHeader {
			packet.longHdrPackets = []*longHeaderPacket{{
				header: &wire.ExtendedHeader{
					Header:       wire.Header{},
					PacketNumber: pn,
				},
				length: 6, // foobar
			}}
		} else {
			packet.shortHdrPacket = &shortHeaderPacket{
				PacketNumber: pn,
				Length:       6,
			}
		}
		return packet
	}

	expectReplaceWithClosed := func() {
		connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(connIDs []protocol.ConnectionID, _ protocol.Perspective, _ []byte) {
			Expect(connIDs).To(ContainElement(srcConnID))
			if len(connIDs) > 1 {
				Expect(connIDs).To(ContainElement(clientDestConnID))
			}
		})
	}

	expectAppendPacket := func(packer *MockPacker, p shortHeaderPacket, b []byte) *gomock.Call {
		return packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), Version1).DoAndReturn(func(buf *packetBuffer, _ protocol.ByteCount, _ protocol.VersionNumber) (shortHeaderPacket, error) {
			buf.Data = append(buf.Data, b...)
			return p, nil
		})
	}

	enableGSO := func() { capabilities = connCapabilities{GSO: true} }

	BeforeEach(func() {
		Eventually(areConnsRunning).Should(BeFalse())

		connRunner = NewMockConnRunner(mockCtrl)
		mconn = NewMockSendConn(mockCtrl)
		mconn.EXPECT().capabilities().DoAndReturn(func() connCapabilities { return capabilities }).AnyTimes()
		mconn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
		mconn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
		tokenGenerator, err := handshake.NewTokenGenerator(rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().SentTransportParameters(gomock.Any())
		tracer.EXPECT().UpdatedKeyFromTLS(gomock.Any(), gomock.Any()).AnyTimes()
		tracer.EXPECT().UpdatedCongestionState(gomock.Any())
		conn = newConnection(
			mconn,
			connRunner,
			protocol.ConnectionID{},
			nil,
			clientDestConnID,
			destConnID,
			srcConnID,
			&protocol.DefaultConnectionIDGenerator{},
			protocol.StatelessResetToken{},
			populateServerConfig(&Config{DisablePathMTUDiscovery: true}),
			&tls.Config{},
			tokenGenerator,
			false,
			tracer,
			1234,
			utils.DefaultLogger,
			protocol.Version1,
		).(*connection)
		streamManager = NewMockStreamManager(mockCtrl)
		conn.streamsMap = streamManager
		packer = NewMockPacker(mockCtrl)
		conn.packer = packer
		cryptoSetup = mocks.NewMockCryptoSetup(mockCtrl)
		conn.cryptoStreamHandler = cryptoSetup
		conn.handshakeComplete = true
		conn.idleTimeout = time.Hour
	})

	AfterEach(func() {
		Eventually(areConnsRunning).Should(BeFalse())
		capabilities = connCapabilities{}
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
				Expect(conn.handleStreamFrame(f)).To(Succeed())
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
				Expect(conn.handleStreamFrame(f)).To(MatchError(testErr))
			})

			It("ignores STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(5)).Return(nil, nil) // for closed streams, the streamManager returns nil
				Expect(conn.handleStreamFrame(&wire.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar"),
				})).To(Succeed())
			})
		})

		Context("handling ACK frames", func() {
			It("informs the SentPacketHandler about ACKs", func() {
				f := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}}
				sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
				sph.EXPECT().ReceivedAck(f, protocol.EncryptionHandshake, gomock.Any())
				conn.sentPacketHandler = sph
				err := conn.handleAckFrame(f, protocol.EncryptionHandshake)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("handling RESET_STREAM frames", func() {
			It("closes the streams for writing", func() {
				f := &wire.ResetStreamFrame{
					StreamID:  555,
					ErrorCode: 42,
					FinalSize: 0x1337,
				}
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(555)).Return(str, nil)
				str.EXPECT().handleResetStreamFrame(f)
				err := conn.handleResetStreamFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("returns errors", func() {
				f := &wire.ResetStreamFrame{
					StreamID:  7,
					FinalSize: 0x1337,
				}
				testErr := errors.New("flow control violation")
				str := NewMockReceiveStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(7)).Return(str, nil)
				str.EXPECT().handleResetStreamFrame(f).Return(testErr)
				err := conn.handleResetStreamFrame(f)
				Expect(err).To(MatchError(testErr))
			})

			It("ignores RESET_STREAM frames for closed streams", func() {
				streamManager.EXPECT().GetOrOpenReceiveStream(protocol.StreamID(3)).Return(nil, nil)
				Expect(conn.handleFrame(&wire.ResetStreamFrame{
					StreamID:  3,
					ErrorCode: 42,
				}, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			})
		})

		Context("handling MAX_DATA and MAX_STREAM_DATA frames", func() {
			var connFC *mocks.MockConnectionFlowController

			BeforeEach(func() {
				connFC = mocks.NewMockConnectionFlowController(mockCtrl)
				conn.connFlowController = connFC
			})

			It("updates the flow control window of a stream", func() {
				f := &wire.MaxStreamDataFrame{
					StreamID:          12345,
					MaximumStreamData: 0x1337,
				}
				str := NewMockSendStreamI(mockCtrl)
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(12345)).Return(str, nil)
				str.EXPECT().updateSendWindow(protocol.ByteCount(0x1337))
				Expect(conn.handleMaxStreamDataFrame(f)).To(Succeed())
			})

			It("updates the flow control window of the connection", func() {
				offset := protocol.ByteCount(0x800000)
				connFC.EXPECT().UpdateSendWindow(offset)
				conn.handleMaxDataFrame(&wire.MaxDataFrame{MaximumData: offset})
			})

			It("ignores MAX_STREAM_DATA frames for a closed stream", func() {
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(10)).Return(nil, nil)
				Expect(conn.handleFrame(&wire.MaxStreamDataFrame{
					StreamID:          10,
					MaximumStreamData: 1337,
				}, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			})
		})

		Context("handling MAX_STREAM_ID frames", func() {
			It("passes the frame to the streamsMap", func() {
				f := &wire.MaxStreamsFrame{
					Type:         protocol.StreamTypeUni,
					MaxStreamNum: 10,
				}
				streamManager.EXPECT().HandleMaxStreamsFrame(f)
				conn.handleMaxStreamsFrame(f)
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
				err := conn.handleStopSendingFrame(f)
				Expect(err).ToNot(HaveOccurred())
			})

			It("ignores STOP_SENDING frames for a closed stream", func() {
				streamManager.EXPECT().GetOrOpenSendStream(protocol.StreamID(3)).Return(nil, nil)
				Expect(conn.handleFrame(&wire.StopSendingFrame{
					StreamID:  3,
					ErrorCode: 1337,
				}, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			})
		})

		It("handles NEW_CONNECTION_ID frames", func() {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
			Expect(conn.handleFrame(&wire.NewConnectionIDFrame{
				SequenceNumber: 10,
				ConnectionID:   connID,
			}, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			Expect(conn.connIDManager.queue.Back().Value.ConnectionID).To(Equal(connID))
		})

		It("handles PING frames", func() {
			err := conn.handleFrame(&wire.PingFrame{}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("rejects PATH_RESPONSE frames", func() {
			err := conn.handleFrame(&wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).To(MatchError("unexpected PATH_RESPONSE frame"))
		})

		It("handles PATH_CHALLENGE frames", func() {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			err := conn.handleFrame(&wire.PathChallengeFrame{Data: data}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).ToNot(HaveOccurred())
			frames, _ := conn.framer.AppendControlFrames(nil, 1000, protocol.Version1)
			Expect(frames).To(Equal([]ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: data}}}))
		})

		It("rejects NEW_TOKEN frames", func() {
			err := conn.handleNewTokenFrame(&wire.NewTokenFrame{})
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
			Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.ProtocolViolation))
		})

		It("handles BLOCKED frames", func() {
			err := conn.handleFrame(&wire.DataBlockedFrame{}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAM_BLOCKED frames", func() {
			err := conn.handleFrame(&wire.StreamDataBlockedFrame{}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles STREAMS_BLOCKED frames", func() {
			err := conn.handleFrame(&wire.StreamsBlockedFrame{}, protocol.Encryption1RTT, protocol.ConnectionID{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles CONNECTION_CLOSE frames, with a transport error code", func() {
			expectedErr := &qerr.TransportError{
				Remote:       true,
				ErrorCode:    qerr.StreamLimitError,
				ErrorMessage: "foobar",
			}
			streamManager.EXPECT().CloseWithError(expectedErr)
			connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(connIDs []protocol.ConnectionID, _ protocol.Perspective, _ []byte) {
				Expect(connIDs).To(ConsistOf(clientDestConnID, srcConnID))
			})
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(expectedErr),
				tracer.EXPECT().Close(),
			)

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				Expect(conn.run()).To(MatchError(expectedErr))
			}()
			Expect(conn.handleFrame(&wire.ConnectionCloseFrame{
				ErrorCode:    uint64(qerr.StreamLimitError),
				ReasonPhrase: "foobar",
			}, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("handles CONNECTION_CLOSE frames, with an application error code", func() {
			testErr := &qerr.ApplicationError{
				Remote:       true,
				ErrorCode:    0x1337,
				ErrorMessage: "foobar",
			}
			streamManager.EXPECT().CloseWithError(testErr)
			connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(connIDs []protocol.ConnectionID, _ protocol.Perspective, _ []byte) {
				Expect(connIDs).To(ConsistOf(clientDestConnID, srcConnID))
			})
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(testErr),
				tracer.EXPECT().Close(),
			)

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				Expect(conn.run()).To(MatchError(testErr))
			}()
			ccf := &wire.ConnectionCloseFrame{
				ErrorCode:          0x1337,
				ReasonPhrase:       "foobar",
				IsApplicationError: true,
			}
			Expect(conn.handleFrame(ccf, protocol.Encryption1RTT, protocol.ConnectionID{})).To(Succeed())
			Eventually(conn.Context().Done()).Should(BeClosed())
			Expect(context.Cause(conn.Context())).To(MatchError(testErr))
		})

		It("errors on HANDSHAKE_DONE frames", func() {
			Expect(conn.handleHandshakeDoneFrame()).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received a HANDSHAKE_DONE frame",
			}))
		})
	})

	It("tells its versions", func() {
		conn.version = 4242
		Expect(conn.GetVersion()).To(Equal(protocol.VersionNumber(4242)))
	})

	Context("closing", func() {
		var (
			runErr         chan error
			expectedRunErr error
		)

		BeforeEach(func() {
			runErr = make(chan error, 1)
			expectedRunErr = nil
		})

		AfterEach(func() {
			if expectedRunErr != nil {
				Eventually(runErr).Should(Receive(MatchError(expectedRunErr)))
			} else {
				Eventually(runErr).Should(Receive())
			}
		})

		runConn := func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				runErr <- conn.run()
			}()
			Eventually(areConnsRunning).Should(BeTrue())
		}

		It("shuts down without error", func() {
			conn.handshakeComplete = true
			runConn()
			streamManager.EXPECT().CloseWithError(&qerr.ApplicationError{})
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			buffer := getPacketBuffer()
			buffer.Data = append(buffer.Data, []byte("connection close")...)
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(e *qerr.ApplicationError, _ protocol.ByteCount, _ protocol.VersionNumber) (*coalescedPacket, error) {
				Expect(e.ErrorCode).To(BeEquivalentTo(qerr.NoError))
				Expect(e.ErrorMessage).To(BeEmpty())
				return &coalescedPacket{buffer: buffer}, nil
			})
			mconn.EXPECT().Write([]byte("connection close"), gomock.Any())
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					var appErr *ApplicationError
					Expect(errors.As(e, &appErr)).To(BeTrue())
					Expect(appErr.Remote).To(BeFalse())
					Expect(appErr.ErrorCode).To(BeZero())
				}),
				tracer.EXPECT().Close(),
			)
			conn.shutdown()
			Eventually(areConnsRunning).Should(BeFalse())
			Expect(conn.Context().Done()).To(BeClosed())
		})

		It("only closes once", func() {
			runConn()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.shutdown()
			conn.shutdown()
			Eventually(areConnsRunning).Should(BeFalse())
			Expect(conn.Context().Done()).To(BeClosed())
		})

		It("closes with an error", func() {
			runConn()
			expectedErr := &qerr.ApplicationError{
				ErrorCode:    0x1337,
				ErrorMessage: "test error",
			}
			streamManager.EXPECT().CloseWithError(expectedErr)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackApplicationClose(expectedErr, gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(expectedErr),
				tracer.EXPECT().Close(),
			)
			conn.CloseWithError(0x1337, "test error")
			Eventually(areConnsRunning).Should(BeFalse())
			Expect(conn.Context().Done()).To(BeClosed())
			Expect(context.Cause(conn.Context())).To(MatchError(expectedErr))
		})

		It("includes the frame type in transport-level close frames", func() {
			runConn()
			expectedErr := &qerr.TransportError{
				ErrorCode:    0x1337,
				FrameType:    0x42,
				ErrorMessage: "test error",
			}
			streamManager.EXPECT().CloseWithError(expectedErr)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(expectedErr, gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(expectedErr),
				tracer.EXPECT().Close(),
			)
			conn.closeLocal(expectedErr)
			Eventually(areConnsRunning).Should(BeFalse())
			Expect(conn.Context().Done()).To(BeClosed())
		})

		It("destroys the connection", func() {
			runConn()
			testErr := errors.New("close")
			streamManager.EXPECT().CloseWithError(gomock.Any())
			connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			// don't EXPECT any calls to mconn.Write()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					var transportErr *TransportError
					Expect(errors.As(e, &transportErr)).To(BeTrue())
					Expect(transportErr.Remote).To(BeFalse())
					Expect(transportErr.ErrorCode).To(Equal(qerr.InternalError))
				}),
				tracer.EXPECT().Close(),
			)
			conn.destroy(testErr)
			Eventually(areConnsRunning).Should(BeFalse())
			expectedRunErr = &qerr.TransportError{
				ErrorCode:    qerr.InternalError,
				ErrorMessage: testErr.Error(),
			}
		})

		It("cancels the context when the run loop exists", func() {
			runConn()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			returned := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				ctx := conn.Context()
				<-ctx.Done()
				Expect(ctx.Err()).To(MatchError(context.Canceled))
				close(returned)
			}()
			Consistently(returned).ShouldNot(BeClosed())
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.shutdown()
			Eventually(returned).Should(BeClosed())
			Expect(context.Cause(conn.Context())).To(MatchError(context.Canceled))
		})

		It("doesn't send any more packets after receiving a CONNECTION_CLOSE", func() {
			unpacker := NewMockUnpacker(mockCtrl)
			conn.handshakeConfirmed = true
			conn.unpacker = unpacker
			runConn()
			cryptoSetup.EXPECT().Close()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			b, err := wire.AppendShortHeader(nil, srcConnID, 42, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
			Expect(err).ToNot(HaveOccurred())

			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(time.Time, []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				b, err := (&wire.ConnectionCloseFrame{ErrorCode: uint64(qerr.StreamLimitError)}).Append(nil, conn.version)
				Expect(err).ToNot(HaveOccurred())
				return 3, protocol.PacketNumberLen2, protocol.KeyPhaseOne, b, nil
			})
			gomock.InOrder(
				tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any()),
				tracer.EXPECT().ClosedConnection(gomock.Any()),
				tracer.EXPECT().Close(),
			)
			// don't EXPECT any calls to packer.PackPacket()
			conn.handlePacket(receivedPacket{
				rcvTime:    time.Now(),
				remoteAddr: &net.UDPAddr{},
				buffer:     getPacketBuffer(),
				data:       b,
			})
			// Consistently(pack).ShouldNot(Receive())
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("closes when the sendQueue encounters an error", func() {
			conn.handshakeConfirmed = true
			sconn := NewMockSendConn(mockCtrl)
			sconn.EXPECT().capabilities().AnyTimes()
			sconn.EXPECT().Write(gomock.Any(), gomock.Any()).Return(io.ErrClosedPipe).AnyTimes()
			conn.sendQueue = newSendQueue(sconn)
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().Return(time.Now().Add(time.Hour)).AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			// only expect a single SentPacket() call
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			conn.sentPacketHandler = sph
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1}, []byte("foobar"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
			runConn()
			conn.queueControlFrame(&wire.PingFrame{})
			conn.scheduleSending()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("closes due to a stateless reset", func() {
			token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			runConn()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					var srErr *StatelessResetError
					Expect(errors.As(e, &srErr)).To(BeTrue())
					Expect(srErr.Token).To(Equal(token))
				}),
				tracer.EXPECT().Close(),
			)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			conn.destroy(&StatelessResetError{Token: token})
		})
	})

	Context("receiving packets", func() {
		var unpacker *MockUnpacker

		BeforeEach(func() {
			unpacker = NewMockUnpacker(mockCtrl)
			conn.unpacker = unpacker
		})

		getShortHeaderPacket := func(connID protocol.ConnectionID, pn protocol.PacketNumber, data []byte) receivedPacket {
			b, err := wire.AppendShortHeader(nil, connID, pn, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
			Expect(err).ToNot(HaveOccurred())
			return receivedPacket{
				data:    append(b, data...),
				buffer:  getPacketBuffer(),
				rcvTime: time.Now(),
			}
		}

		getLongHeaderPacket := func(extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
			b, err := extHdr.Append(nil, conn.version)
			Expect(err).ToNot(HaveOccurred())
			return receivedPacket{
				data:    append(b, data...),
				buffer:  getPacketBuffer(),
				rcvTime: time.Now(),
			}
		}

		It("drops Retry packets", func() {
			p := getLongHeaderPacket(&wire.ExtendedHeader{Header: wire.Header{
				Type:             protocol.PacketTypeRetry,
				DestConnectionID: destConnID,
				SrcConnectionID:  srcConnID,
				Version:          conn.version,
				Token:            []byte("foobar"),
			}}, make([]byte, 16) /* Retry integrity tag */)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, p.Size(), logging.PacketDropUnexpectedPacket)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("drops Version Negotiation packets", func() {
			b := wire.ComposeVersionNegotiation(
				protocol.ArbitraryLenConnectionID(srcConnID.Bytes()),
				protocol.ArbitraryLenConnectionID(destConnID.Bytes()),
				conn.config.Versions,
			)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, protocol.ByteCount(len(b)), logging.PacketDropUnexpectedPacket)
			Expect(conn.handlePacketImpl(receivedPacket{
				data:   b,
				buffer: getPacketBuffer(),
			})).To(BeFalse())
		})

		It("drops packets for which header decryption fails", func() {
			p := getLongHeaderPacket(&wire.ExtendedHeader{
				Header: wire.Header{
					Type:    protocol.PacketTypeHandshake,
					Version: conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}, nil)
			p.data[0] ^= 0x40 // unset the QUIC bit
			tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropHeaderParseError)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("drops packets for which the version is unsupported", func() {
			p := getLongHeaderPacket(&wire.ExtendedHeader{
				Header: wire.Header{
					Type:    protocol.PacketTypeHandshake,
					Version: conn.version + 1,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}, nil)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropUnsupportedVersion)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("drops packets with an unsupported version", func() {
			origSupportedVersions := make([]protocol.VersionNumber, len(protocol.SupportedVersions))
			copy(origSupportedVersions, protocol.SupportedVersions)
			defer func() {
				protocol.SupportedVersions = origSupportedVersions
			}()

			protocol.SupportedVersions = append(protocol.SupportedVersions, conn.version+1)
			p := getLongHeaderPacket(&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Version:          conn.version + 1,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}, nil)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeHandshake, p.Size(), logging.PacketDropUnexpectedVersion)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("informs the ReceivedPacketHandler about non-ack-eliciting packets", func() {
			hdr := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: srcConnID,
					Version:          protocol.Version1,
					Length:           1,
				},
				PacketNumber:    0x37,
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			unpackedHdr := *hdr
			unpackedHdr.PacketNumber = 0x1337
			packet := getLongHeaderPacket(hdr, nil)
			packet.ecn = protocol.ECNCE
			rcvTime := time.Now().Add(-10 * time.Second)
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), rcvTime, gomock.Any(), conn.version).Return(&unpackedPacket{
				encryptionLevel: protocol.EncryptionInitial,
				hdr:             &unpackedHdr,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			gomock.InOrder(
				rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial),
				rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECNCE, protocol.EncryptionInitial, rcvTime, false),
			)
			conn.receivedPacketHandler = rph
			packet.rcvTime = rcvTime
			tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), []logging.Frame{})
			Expect(conn.handlePacketImpl(packet)).To(BeTrue())
		})

		It("informs the ReceivedPacketHandler about ack-eliciting packets", func() {
			rcvTime := time.Now().Add(-10 * time.Second)
			b, err := (&wire.PingFrame{}).Append(nil, conn.version)
			Expect(err).ToNot(HaveOccurred())
			packet := getShortHeaderPacket(srcConnID, 0x37, nil)
			packet.ecn = protocol.ECT1
			unpacker.EXPECT().UnpackShortHeader(rcvTime, gomock.Any()).Return(protocol.PacketNumber(0x1337), protocol.PacketNumberLen2, protocol.KeyPhaseZero, b, nil)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			gomock.InOrder(
				rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.Encryption1RTT),
				rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECT1, protocol.Encryption1RTT, rcvTime, true),
			)
			conn.receivedPacketHandler = rph
			packet.rcvTime = rcvTime
			tracer.EXPECT().ReceivedShortHeaderPacket(&logging.ShortHeader{PacketNumber: 0x1337, PacketNumberLen: 2, KeyPhase: protocol.KeyPhaseZero}, protocol.ByteCount(len(packet.data)), []logging.Frame{&logging.PingFrame{}})
			Expect(conn.handlePacketImpl(packet)).To(BeTrue())
		})

		It("drops duplicate packets", func() {
			packet := getShortHeaderPacket(srcConnID, 0x37, nil)
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0x1337), protocol.PacketNumberLen2, protocol.KeyPhaseOne, []byte("foobar"), nil)
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.Encryption1RTT).Return(true)
			conn.receivedPacketHandler = rph
			tracer.EXPECT().DroppedPacket(logging.PacketType1RTT, protocol.ByteCount(len(packet.data)), logging.PacketDropDuplicate)
			Expect(conn.handlePacketImpl(packet)).To(BeFalse())
		})

		It("drops a packet when unpacking fails", func() {
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(nil, handshake.ErrDecryptionFailed)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			expectReplaceWithClosed()
			p := getLongHeaderPacket(&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: srcConnID,
					Version:          conn.version,
					Length:           2 + 6,
				},
				PacketNumber:    0x1337,
				PacketNumberLen: protocol.PacketNumberLen2,
			}, []byte("foobar"))
			tracer.EXPECT().DroppedPacket(logging.PacketTypeHandshake, p.Size(), logging.PacketDropPayloadDecryptError)
			conn.handlePacket(p)
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			conn.closeLocal(errors.New("close"))
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("processes multiple received packets before sending one", func() {
			conn.creationTime = time.Now()
			var pn protocol.PacketNumber
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				pn++
				return pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* PADDING frame */, nil
			}).Times(3)
			tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(hdr *logging.ShortHeader, _ protocol.ByteCount, _ []logging.Frame) {
			}).Times(3)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version) // only expect a single call

			for i := 0; i < 3; i++ {
				conn.handlePacket(getShortHeaderPacket(srcConnID, 0x1337+protocol.PacketNumber(i), []byte("foobar")))
			}

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())

			// make the go routine return
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			conn.closeLocal(errors.New("close"))
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("doesn't processes multiple received packets before sending one before handshake completion", func() {
			conn.handshakeComplete = false
			conn.creationTime = time.Now()
			var pn protocol.PacketNumber
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				pn++
				return pn, protocol.PacketNumberLen4, protocol.KeyPhaseZero, []byte{0} /* PADDING frame */, nil
			}).Times(3)
			tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(hdr *logging.ShortHeader, _ protocol.ByteCount, _ []logging.Frame) {
			}).Times(3)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).Times(3)

			for i := 0; i < 3; i++ {
				conn.handlePacket(getShortHeaderPacket(srcConnID, 0x1337+protocol.PacketNumber(i), []byte("foobar")))
			}

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())

			// make the go routine return
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			conn.closeLocal(errors.New("close"))
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("closes the connection when unpacking fails because the reserved bits were incorrect", func() {
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, wire.ErrInvalidReservedBits)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				err := conn.run()
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
				Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.ProtocolViolation))
				close(done)
			}()
			expectReplaceWithClosed()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			packet := getShortHeaderPacket(srcConnID, 0x42, nil)
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.handlePacket(packet)
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("ignores packets when unpacking the header fails", func() {
			testErr := &headerParseError{errors.New("test error")}
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, testErr)
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			runErr := make(chan error)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				runErr <- conn.run()
			}()
			expectReplaceWithClosed()
			tracer.EXPECT().DroppedPacket(logging.PacketType1RTT, gomock.Any(), logging.PacketDropHeaderParseError)
			conn.handlePacket(getShortHeaderPacket(srcConnID, 0x42, nil))
			Consistently(runErr).ShouldNot(Receive())
			// make the go routine return
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("closes the connection when unpacking fails because of an error other than a decryption error", func() {
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
			streamManager.EXPECT().CloseWithError(gomock.Any())
			cryptoSetup.EXPECT().Close()
			packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				err := conn.run()
				Expect(err).To(HaveOccurred())
				Expect(err).To(BeAssignableToTypeOf(&qerr.TransportError{}))
				Expect(err.(*qerr.TransportError).ErrorCode).To(Equal(qerr.ConnectionIDLimitError))
				close(done)
			}()
			expectReplaceWithClosed()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.handlePacket(getShortHeaderPacket(srcConnID, 0x42, nil))
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("ignores packets with a different source connection ID", func() {
			hdr1 := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			hdr2 := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
					Length:           1,
					Version:          conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    2,
			}
			Expect(srcConnID).ToNot(Equal(hdr2.SrcConnectionID))
			// Send one packet, which might change the connection ID.
			// only EXPECT one call to the unpacker
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(&unpackedPacket{
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             hdr1,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			p1 := getLongHeaderPacket(hdr1, nil)
			tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(p1.data)), gomock.Any())
			Expect(conn.handlePacketImpl(p1)).To(BeTrue())
			// The next packet has to be ignored, since the source connection ID doesn't match.
			p2 := getLongHeaderPacket(hdr2, nil)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeInitial, protocol.ByteCount(len(p2.data)), logging.PacketDropUnknownConnectionID)
			Expect(conn.handlePacketImpl(p2)).To(BeFalse())
		})

		It("queues undecryptable packets", func() {
			conn.handshakeComplete = false
			hdr := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(nil, handshake.ErrKeysNotYetAvailable)
			packet := getLongHeaderPacket(hdr, nil)
			tracer.EXPECT().BufferedPacket(logging.PacketTypeHandshake, packet.Size())
			Expect(conn.handlePacketImpl(packet)).To(BeFalse())
			Expect(conn.undecryptablePackets).To(Equal([]receivedPacket{packet}))
		})

		Context("updating the remote address", func() {
			It("doesn't support connection migration", func() {
				unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(10), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* one PADDING frame */, nil)
				packet := getShortHeaderPacket(srcConnID, 0x42, nil)
				packet.remoteAddr = &net.IPAddr{IP: net.IPv4(192, 168, 0, 100)}
				tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet.data)), gomock.Any())
				Expect(conn.handlePacketImpl(packet)).To(BeTrue())
			})
		})

		Context("coalesced packets", func() {
			BeforeEach(func() {
				tracer.EXPECT().StartedConnection(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
			})

			getPacketWithLength := func(connID protocol.ConnectionID, length protocol.ByteCount) (int /* header length */, receivedPacket) {
				hdr := &wire.ExtendedHeader{
					Header: wire.Header{
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: connID,
						SrcConnectionID:  destConnID,
						Version:          protocol.Version1,
						Length:           length,
					},
					PacketNumberLen: protocol.PacketNumberLen3,
				}
				hdrLen := hdr.GetLength(conn.version)
				b := make([]byte, 1)
				rand.Read(b)
				packet := getLongHeaderPacket(hdr, bytes.Repeat(b, int(length)-3))
				return int(hdrLen), packet
			}

			It("cuts packets to the right length", func() {
				hdrLen, packet := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
						hdr:             &wire.ExtendedHeader{Header: wire.Header{}},
					}, nil
				})
				cryptoSetup.EXPECT().DiscardInitialKeys()
				tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionInitial)
				tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet.data)), gomock.Any())
				Expect(conn.handlePacketImpl(packet)).To(BeTrue())
			})

			It("handles coalesced packets", func() {
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen1 + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
						hdr: &wire.ExtendedHeader{
							PacketNumber: 1,
							Header:       wire.Header{SrcConnectionID: destConnID},
						},
					}, nil
				})
				hdrLen2, packet2 := getPacketWithLength(srcConnID, 123)
				unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen2 + 123 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
						hdr: &wire.ExtendedHeader{
							PacketNumber: 2,
							Header:       wire.Header{SrcConnectionID: destConnID},
						},
					}, nil
				})
				tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionInitial).AnyTimes()
				cryptoSetup.EXPECT().DiscardInitialKeys().AnyTimes()
				gomock.InOrder(
					tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet1.data)), gomock.Any()),
					tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet2.data)), gomock.Any()),
				)
				packet1.data = append(packet1.data, packet2.data...)
				Expect(conn.handlePacketImpl(packet1)).To(BeTrue())
			})

			It("works with undecryptable packets", func() {
				conn.handshakeComplete = false
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				hdrLen2, packet2 := getPacketWithLength(srcConnID, 123)
				gomock.InOrder(
					unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(nil, handshake.ErrKeysNotYetAvailable),
					unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
						Expect(data).To(HaveLen(hdrLen2 + 123 - 3))
						return &unpackedPacket{
							encryptionLevel: protocol.EncryptionHandshake,
							data:            []byte{0},
							hdr:             &wire.ExtendedHeader{Header: wire.Header{}},
						}, nil
					}),
				)
				tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionInitial).AnyTimes()
				cryptoSetup.EXPECT().DiscardInitialKeys().AnyTimes()
				gomock.InOrder(
					tracer.EXPECT().BufferedPacket(gomock.Any(), protocol.ByteCount(len(packet1.data))),
					tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet2.data)), gomock.Any()),
				)
				packet1.data = append(packet1.data, packet2.data...)
				Expect(conn.handlePacketImpl(packet1)).To(BeTrue())

				Expect(conn.undecryptablePackets).To(HaveLen(1))
				Expect(conn.undecryptablePackets[0].data).To(HaveLen(hdrLen1 + 456 - 3))
			})

			It("ignores coalesced packet parts if the destination connection IDs don't match", func() {
				wrongConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
				Expect(srcConnID).ToNot(Equal(wrongConnID))
				hdrLen1, packet1 := getPacketWithLength(srcConnID, 456)
				unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
					Expect(data).To(HaveLen(hdrLen1 + 456 - 3))
					return &unpackedPacket{
						encryptionLevel: protocol.EncryptionHandshake,
						data:            []byte{0},
						hdr:             &wire.ExtendedHeader{Header: wire.Header{}},
					}, nil
				})
				_, packet2 := getPacketWithLength(wrongConnID, 123)
				tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionInitial).AnyTimes()
				cryptoSetup.EXPECT().DiscardInitialKeys().AnyTimes()
				// don't EXPECT any more calls to unpacker.UnpackLongHeader()
				gomock.InOrder(
					tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), protocol.ByteCount(len(packet1.data)), gomock.Any()),
					tracer.EXPECT().DroppedPacket(gomock.Any(), protocol.ByteCount(len(packet2.data)), logging.PacketDropUnknownConnectionID),
				)
				packet1.data = append(packet1.data, packet2.data...)
				Expect(conn.handlePacketImpl(packet1)).To(BeTrue())
			})
		})
	})

	Context("sending packets", func() {
		var (
			connDone chan struct{}
			sender   *MockSender
		)

		BeforeEach(func() {
			sender = NewMockSender(mockCtrl)
			sender.EXPECT().Run()
			sender.EXPECT().WouldBlock().AnyTimes()
			conn.sendQueue = sender
			connDone = make(chan struct{})
		})

		AfterEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			sender.EXPECT().Close()
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
			Eventually(connDone).Should(BeClosed())
		})

		runConn := func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
				close(connDone)
			}()
		}

		It("sends packets", func() {
			conn.handshakeConfirmed = true
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().TimeUntilSend().AnyTimes()
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			conn.sentPacketHandler = sph
			runConn()
			p := shortHeaderPacket{
				DestConnID:      protocol.ParseConnectionID([]byte{1, 2, 3}),
				PacketNumber:    1337,
				PacketNumberLen: protocol.PacketNumberLen3,
				KeyPhase:        protocol.KeyPhaseOne,
			}
			expectAppendPacket(packer, p, []byte("foobar"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
			sent := make(chan struct{})
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(sent) })
			tracer.EXPECT().SentShortHeaderPacket(&logging.ShortHeader{
				DestConnectionID: p.DestConnID,
				PacketNumber:     p.PacketNumber,
				PacketNumberLen:  p.PacketNumberLen,
				KeyPhase:         p.KeyPhase,
			}, gomock.Any(), nil, []logging.Frame{})
			conn.scheduleSending()
			Eventually(sent).Should(BeClosed())
		})

		It("doesn't send packets if there's nothing to send", func() {
			conn.handshakeConfirmed = true
			runConn()
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
			conn.receivedPacketHandler.ReceivedPacket(0x035e, protocol.ECNNon, protocol.Encryption1RTT, time.Now(), true)
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure there are no calls to mconn.Write()
		})

		It("sends ACK only packets", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().TimeUntilSend().AnyTimes()
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
			done := make(chan struct{})
			packer.EXPECT().PackCoalescedPacket(true, gomock.Any(), conn.version).Do(func(bool, protocol.ByteCount, protocol.VersionNumber) { close(done) })
			conn.sentPacketHandler = sph
			runConn()
			conn.scheduleSending()
			Eventually(done).Should(BeClosed())
		})

		It("adds a BLOCKED frame when it is connection-level flow control blocked", func() {
			conn.handshakeConfirmed = true
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().TimeUntilSend().AnyTimes()
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			conn.sentPacketHandler = sph
			fc := mocks.NewMockConnectionFlowController(mockCtrl)
			fc.EXPECT().IsNewlyBlocked().Return(true, protocol.ByteCount(1337))
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 13}, []byte("foobar"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
			conn.connFlowController = fc
			runConn()
			sent := make(chan struct{})
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(sent) })
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), nil, []logging.Frame{})
			conn.scheduleSending()
			Eventually(sent).Should(BeClosed())
			frames, _ := conn.framer.AppendControlFrames(nil, 1000, protocol.Version1)
			Expect(frames).To(Equal([]ackhandler.Frame{{Frame: &logging.DataBlockedFrame{MaximumData: 1337}}}))
		})

		It("doesn't send when the SentPacketHandler doesn't allow it", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone).AnyTimes()
			sph.EXPECT().TimeUntilSend().AnyTimes()
			conn.sentPacketHandler = sph
			runConn()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond)
		})

		for _, enc := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
			encLevel := enc

			Context(fmt.Sprintf("sending %s probe packets", encLevel), func() {
				var sendMode ackhandler.SendMode
				var getFrame func(protocol.ByteCount, protocol.VersionNumber) wire.Frame

				BeforeEach(func() {
					//nolint:exhaustive
					switch encLevel {
					case protocol.EncryptionInitial:
						sendMode = ackhandler.SendPTOInitial
						getFrame = conn.retransmissionQueue.GetInitialFrame
					case protocol.EncryptionHandshake:
						sendMode = ackhandler.SendPTOHandshake
						getFrame = conn.retransmissionQueue.GetHandshakeFrame
					case protocol.Encryption1RTT:
						sendMode = ackhandler.SendPTOAppData
						getFrame = conn.retransmissionQueue.GetAppDataFrame
					}
				})

				It("sends a probe packet", func() {
					sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
					sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
					sph.EXPECT().TimeUntilSend().AnyTimes()
					sph.EXPECT().SendMode(gomock.Any()).Return(sendMode)
					sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
					sph.EXPECT().QueueProbePacket(encLevel)
					p := getCoalescedPacket(123, enc != protocol.Encryption1RTT)
					packer.EXPECT().MaybePackProbePacket(encLevel, gomock.Any(), conn.version).Return(p, nil)
					sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ time.Time, pn, _ protocol.PacketNumber, _ []ackhandler.StreamFrame, _ []ackhandler.Frame, _ protocol.EncryptionLevel, _ protocol.ByteCount, _ bool) {
						Expect(pn).To(Equal(protocol.PacketNumber(123)))
					})
					conn.sentPacketHandler = sph
					runConn()
					sent := make(chan struct{})
					sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(sent) })
					if enc == protocol.Encryption1RTT {
						tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), p.shortHdrPacket.Length, gomock.Any(), gomock.Any())
					} else {
						tracer.EXPECT().SentLongHeaderPacket(gomock.Any(), p.longHdrPackets[0].length, gomock.Any(), gomock.Any())
					}
					conn.scheduleSending()
					Eventually(sent).Should(BeClosed())
				})

				It("sends a PING as a probe packet", func() {
					sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
					sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
					sph.EXPECT().TimeUntilSend().AnyTimes()
					sph.EXPECT().SendMode(gomock.Any()).Return(sendMode)
					sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
					sph.EXPECT().QueueProbePacket(encLevel).Return(false)
					p := getCoalescedPacket(123, enc != protocol.Encryption1RTT)
					packer.EXPECT().MaybePackProbePacket(encLevel, gomock.Any(), conn.version).Return(p, nil)
					sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ time.Time, pn, _ protocol.PacketNumber, _ []ackhandler.StreamFrame, _ []ackhandler.Frame, _ protocol.EncryptionLevel, _ protocol.ByteCount, _ bool) {
						Expect(pn).To(Equal(protocol.PacketNumber(123)))
					})
					conn.sentPacketHandler = sph
					runConn()
					sent := make(chan struct{})
					sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(sent) })
					if enc == protocol.Encryption1RTT {
						tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), p.shortHdrPacket.Length, gomock.Any(), gomock.Any())
					} else {
						tracer.EXPECT().SentLongHeaderPacket(gomock.Any(), p.longHdrPackets[0].length, gomock.Any(), gomock.Any())
					}
					conn.scheduleSending()
					Eventually(sent).Should(BeClosed())
					// We're using a mock packet packer in this test.
					// We therefore need to test separately that the PING was actually queued.
					Expect(getFrame(1000, protocol.Version1)).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				})
			})
		}
	})

	Context("packet pacing", func() {
		var (
			sph    *mockackhandler.MockSentPacketHandler
			sender *MockSender
		)

		BeforeEach(func() {
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			sph = mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			conn.handshakeConfirmed = true
			conn.handshakeComplete = true
			conn.sentPacketHandler = sph
			sender = NewMockSender(mockCtrl)
			sender.EXPECT().Run()
			conn.sendQueue = sender
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		AfterEach(func() {
			// make the go routine return
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			sender.EXPECT().Close()
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("sends multiple packets one by one immediately", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(2)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited)
			sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, []byte("packet10"))
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 11}, []byte("packet11"))
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(b *packetBuffer, _ protocol.ByteCount) {
				Expect(b.Data).To(Equal([]byte("packet10")))
			})
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(b *packetBuffer, _ protocol.ByteCount) {
				Expect(b.Data).To(Equal([]byte("packet11")))
			})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 2 packets are sent
		})

		It("sends multiple packets one by one immediately, with GSO", func() {
			enableGSO()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(3)
			payload1 := make([]byte, conn.mtuDiscoverer.CurrentSize())
			rand.Read(payload1)
			payload2 := make([]byte, conn.mtuDiscoverer.CurrentSize())
			rand.Read(payload2)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, payload1)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 11}, payload2)
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), conn.mtuDiscoverer.CurrentSize()).Do(func(b *packetBuffer, l protocol.ByteCount) {
				Expect(b.Data).To(Equal(append(payload1, payload2...)))
			})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 2 packets are sent
		})

		It("stops appending packets when a smaller packet is packed, with GSO", func() {
			enableGSO()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(2)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
			payload1 := make([]byte, conn.mtuDiscoverer.CurrentSize())
			rand.Read(payload1)
			payload2 := make([]byte, conn.mtuDiscoverer.CurrentSize()-1)
			rand.Read(payload2)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, payload1)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 11}, payload2)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), conn.mtuDiscoverer.CurrentSize()).Do(func(b *packetBuffer, l protocol.ByteCount) {
				Expect(b.Data).To(Equal(append(payload1, payload2...)))
			})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 2 packets are sent
		})

		It("sends multiple packets, when the pacer allows immediate sending", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(2)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, []byte("packet10"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any())
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 1 packet is sent
		})

		It("allows an ACK to be sent when pacing limited", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited)
			packer.EXPECT().PackAckOnlyPacket(gomock.Any(), conn.version).Return(shortHeaderPacket{PacketNumber: 123}, getPacketBuffer(), nil)

			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any())
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 1 packet is sent
		})

		// when becoming congestion limited, at some point the SendMode will change from SendAny to SendAck
		// we shouldn't send the ACK in the same run
		It("doesn't send an ACK right after becoming congestion limited", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAck)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 100}, []byte("packet100"))
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any())
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			time.Sleep(50 * time.Millisecond) // make sure that only 1 packet is sent
		})

		It("paces packets", func() {
			pacingDelay := scaleDuration(100 * time.Millisecond)
			gomock.InOrder(
				sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
				expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 100}, []byte("packet100")),
				sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
				sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(pacingDelay)),
				sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
				expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 101}, []byte("packet101")),
				sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()),
				sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited),
				sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour)),
			)
			written := make(chan struct{}, 2)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { written <- struct{}{} }).Times(2)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			Eventually(written).Should(HaveLen(1))
			Consistently(written, pacingDelay/2).Should(HaveLen(1))
			Eventually(written, 2*pacingDelay).Should(HaveLen(2))
		})

		It("sends multiple packets at once", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).Times(3)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendPacingLimited)
			sph.EXPECT().TimeUntilSend().Return(time.Now().Add(time.Hour))
			for pn := protocol.PacketNumber(1000); pn < 1003; pn++ {
				expectAppendPacket(packer, shortHeaderPacket{PacketNumber: pn}, []byte("packet"))
			}
			written := make(chan struct{}, 3)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { written <- struct{}{} }).Times(3)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			Eventually(written).Should(HaveLen(3))
		})

		for _, withGSO := range []bool{false, true} {
			withGSO := withGSO
			It(fmt.Sprintf("doesn't try to send if the send queue is full: %t", withGSO), func() {
				if withGSO {
					enableGSO()
				}
				available := make(chan struct{}, 1)
				sender.EXPECT().WouldBlock().Return(true)
				sender.EXPECT().Available().Return(available)
				go func() {
					defer GinkgoRecover()
					cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
					cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
					conn.run()
				}()
				conn.scheduleSending()
				time.Sleep(scaleDuration(50 * time.Millisecond))

				written := make(chan struct{})
				sender.EXPECT().WouldBlock().AnyTimes()
				sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
				expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1000}, []byte("packet1000"))
				packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
				sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { close(written) })
				available <- struct{}{}
				Eventually(written).Should(BeClosed())
			})
		}

		It("stops sending when there are new packets to receive", func() {
			sender.EXPECT().WouldBlock().AnyTimes()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()

			written := make(chan struct{})
			sender.EXPECT().WouldBlock().AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(time.Time, protocol.PacketNumber, protocol.PacketNumber, []ackhandler.StreamFrame, []ackhandler.Frame, protocol.EncryptionLevel, protocol.ByteCount, bool) {
				sph.EXPECT().ReceivedBytes(gomock.Any())
				conn.handlePacket(receivedPacket{buffer: getPacketBuffer()})
			})
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, []byte("packet10"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { close(written) })

			conn.scheduleSending()
			time.Sleep(scaleDuration(50 * time.Millisecond))

			Eventually(written).Should(BeClosed())
		})

		It("stops sending when the send queue is full", func() {
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny)
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1000}, []byte("packet1000"))
			written := make(chan struct{}, 1)
			sender.EXPECT().WouldBlock()
			sender.EXPECT().WouldBlock().Return(true).Times(2)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { written <- struct{}{} })
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			available := make(chan struct{}, 1)
			sender.EXPECT().Available().Return(available)
			conn.scheduleSending()
			Eventually(written).Should(Receive())
			time.Sleep(scaleDuration(50 * time.Millisecond))

			// now make room in the send queue
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sender.EXPECT().WouldBlock().AnyTimes()
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1001}, []byte("packet1001"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { written <- struct{}{} })
			available <- struct{}{}
			Eventually(written).Should(Receive())

			// The send queue is not full any more. Sending on the available channel should have no effect.
			available <- struct{}{}
			time.Sleep(scaleDuration(50 * time.Millisecond))
		})

		It("doesn't set a pacing timer when there is no data to send", func() {
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sender.EXPECT().WouldBlock().AnyTimes()
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			// don't EXPECT any calls to mconn.Write()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending() // no packet will get sent
			time.Sleep(50 * time.Millisecond)
		})

		It("sends a Path MTU probe packet", func() {
			mtuDiscoverer := NewMockMTUDiscoverer(mockCtrl)
			conn.mtuDiscoverer = mtuDiscoverer
			conn.config.DisablePathMTUDiscovery = false
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny)
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
			written := make(chan struct{}, 1)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, protocol.ByteCount) { written <- struct{}{} })
			mtuDiscoverer.EXPECT().ShouldSendProbe(gomock.Any()).Return(true)
			ping := ackhandler.Frame{Frame: &wire.PingFrame{}}
			mtuDiscoverer.EXPECT().GetPing().Return(ping, protocol.ByteCount(1234))
			packer.EXPECT().PackMTUProbePacket(ping, protocol.ByteCount(1234), conn.version).Return(shortHeaderPacket{PacketNumber: 1}, getPacketBuffer(), nil)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending()
			Eventually(written).Should(Receive())
			mtuDiscoverer.EXPECT().CurrentSize().Return(protocol.ByteCount(1234))
		})
	})

	Context("scheduling sending", func() {
		var sender *MockSender

		BeforeEach(func() {
			sender = NewMockSender(mockCtrl)
			sender.EXPECT().WouldBlock().AnyTimes()
			sender.EXPECT().Run()
			conn.sendQueue = sender
			conn.handshakeConfirmed = true
		})

		AfterEach(func() {
			// make the go routine return
			expectReplaceWithClosed()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			sender.EXPECT().Close()
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("sends when scheduleSending is called", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().TimeUntilSend().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()

			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			conn.sentPacketHandler = sph
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1}, []byte("packet1"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			// don't EXPECT any calls to mconn.Write()
			time.Sleep(50 * time.Millisecond)
			// only EXPECT calls after scheduleSending is called
			written := make(chan struct{})
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(written) })
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			conn.scheduleSending()
			Eventually(written).Should(BeClosed())
		})

		It("sets the timer to the ack timer", func() {
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1234}, []byte("packet1234"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ time.Time, pn, _ protocol.PacketNumber, _ []ackhandler.StreamFrame, _ []ackhandler.Frame, _ protocol.EncryptionLevel, _ protocol.ByteCount, _ bool) {
				Expect(pn).To(Equal(protocol.PacketNumber(1234)))
			})
			conn.sentPacketHandler = sph
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(10 * time.Millisecond))
			// make the run loop wait
			rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(time.Hour)).MaxTimes(1)
			conn.receivedPacketHandler = rph

			written := make(chan struct{})
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Do(func(*packetBuffer, protocol.ByteCount) { close(written) })
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Eventually(written).Should(BeClosed())
		})
	})

	It("sends coalesced packets before the handshake is confirmed", func() {
		conn.handshakeComplete = false
		conn.handshakeConfirmed = false
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		conn.sentPacketHandler = sph
		buffer := getPacketBuffer()
		buffer.Data = append(buffer.Data, []byte("foobar")...)
		packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).Return(&coalescedPacket{
			buffer: buffer,
			longHdrPackets: []*longHeaderPacket{
				{
					header: &wire.ExtendedHeader{
						Header:       wire.Header{Type: protocol.PacketTypeInitial},
						PacketNumber: 13,
					},
					length: 123,
				},
				{
					header: &wire.ExtendedHeader{
						Header:       wire.Header{Type: protocol.PacketTypeHandshake},
						PacketNumber: 37,
					},
					length: 1234,
				},
			},
		}, nil)
		packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()

		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().TimeUntilSend().Return(time.Now()).AnyTimes()
		gomock.InOrder(
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ time.Time, pn, _ protocol.PacketNumber, _ []ackhandler.StreamFrame, _ []ackhandler.Frame, encLevel protocol.EncryptionLevel, size protocol.ByteCount, _ bool) {
				Expect(encLevel).To(Equal(protocol.EncryptionInitial))
				Expect(pn).To(Equal(protocol.PacketNumber(13)))
				Expect(size).To(BeEquivalentTo(123))
			}),
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ time.Time, pn, _ protocol.PacketNumber, _ []ackhandler.StreamFrame, _ []ackhandler.Frame, encLevel protocol.EncryptionLevel, size protocol.ByteCount, _ bool) {
				Expect(encLevel).To(Equal(protocol.EncryptionHandshake))
				Expect(pn).To(Equal(protocol.PacketNumber(37)))
				Expect(size).To(BeEquivalentTo(1234))
			}),
		)
		gomock.InOrder(
			tracer.EXPECT().SentLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(hdr *wire.ExtendedHeader, _ protocol.ByteCount, _ *wire.AckFrame, _ []logging.Frame) {
				Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
			}),
			tracer.EXPECT().SentLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(hdr *wire.ExtendedHeader, _ protocol.ByteCount, _ *wire.AckFrame, _ []logging.Frame) {
				Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
			}),
		)

		sent := make(chan struct{})
		mconn.EXPECT().Write([]byte("foobar"), protocol.ByteCount(6)).Do(func([]byte, protocol.ByteCount) { close(sent) })

		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			conn.run()
		}()

		conn.scheduleSending()
		Eventually(sent).Should(BeClosed())

		// make sure the go routine returns
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		mconn.EXPECT().Write(gomock.Any(), gomock.Any())
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		conn.shutdown()
		Eventually(conn.Context().Done()).Should(BeClosed())
	})

	It("cancels the HandshakeComplete context when the handshake completes", func() {
		packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		conn.sentPacketHandler = sph
		tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake)
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SendMode(gomock.Any()).AnyTimes()
		sph.EXPECT().DropPackets(protocol.EncryptionHandshake)
		sph.EXPECT().SetHandshakeConfirmed()
		connRunner.EXPECT().Retire(clientDestConnID)
		cryptoSetup.EXPECT().SetHandshakeConfirmed()
		cryptoSetup.EXPECT().GetSessionTicket()
		handshakeCtx := conn.HandshakeComplete()
		Consistently(handshakeCtx).ShouldNot(BeClosed())
		Expect(conn.handleHandshakeComplete()).To(Succeed())
		Eventually(handshakeCtx).Should(BeClosed())
	})

	It("sends a session ticket when the handshake completes", func() {
		const size = protocol.MaxPostHandshakeCryptoFrameSize * 3 / 2
		packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
		connRunner.EXPECT().Retire(clientDestConnID)
		conn.sentPacketHandler.DropPackets(protocol.EncryptionInitial)
		tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake)
		cryptoSetup.EXPECT().SetHandshakeConfirmed()
		cryptoSetup.EXPECT().GetSessionTicket().Return(make([]byte, size), nil)

		handshakeCtx := conn.HandshakeComplete()
		Consistently(handshakeCtx).ShouldNot(BeClosed())
		Expect(conn.handleHandshakeComplete()).To(Succeed())
		var frames []ackhandler.Frame
		Eventually(func() []ackhandler.Frame {
			frames, _ = conn.framer.AppendControlFrames(nil, protocol.MaxByteCount, protocol.Version1)
			return frames
		}).ShouldNot(BeEmpty())
		var count int
		var s int
		for _, f := range frames {
			if cf, ok := f.Frame.(*wire.CryptoFrame); ok {
				count++
				s += len(cf.Data)
				Expect(f.Frame.Length(conn.version)).To(BeNumerically("<=", protocol.MaxPostHandshakeCryptoFrameSize))
			}
		}
		Expect(size).To(BeEquivalentTo(s))
	})

	It("doesn't cancel the HandshakeComplete context when the handshake fails", func() {
		packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake()
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			conn.run()
		}()
		handshakeCtx := conn.HandshakeComplete()
		Consistently(handshakeCtx).ShouldNot(BeClosed())
		mconn.EXPECT().Write(gomock.Any(), gomock.Any())
		conn.closeLocal(errors.New("handshake error"))
		Consistently(handshakeCtx).ShouldNot(BeClosed())
		Eventually(conn.Context().Done()).Should(BeClosed())
	})

	It("sends a HANDSHAKE_DONE frame when the handshake completes", func() {
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SetHandshakeConfirmed()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		mconn.EXPECT().Write(gomock.Any(), gomock.Any())
		tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		conn.sentPacketHandler = sph
		done := make(chan struct{})
		connRunner.EXPECT().Retire(clientDestConnID)
		packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(_ *packetBuffer, _ protocol.ByteCount, v protocol.VersionNumber) (shortHeaderPacket, error) {
			frames, _ := conn.framer.AppendControlFrames(nil, protocol.MaxByteCount, v)
			Expect(frames).ToNot(BeEmpty())
			Expect(frames[0].Frame).To(BeEquivalentTo(&wire.HandshakeDoneFrame{}))
			defer close(done)
			return shortHeaderPacket{}, nil
		})
		packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
		tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake)
		sph.EXPECT().DropPackets(protocol.EncryptionHandshake)
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake()
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete})
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			cryptoSetup.EXPECT().SetHandshakeConfirmed()
			cryptoSetup.EXPECT().GetSessionTicket()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			Expect(conn.handleHandshakeComplete()).To(Succeed())
			conn.run()
		}()
		Eventually(done).Should(BeClosed())
		// make sure the go routine returns
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		conn.shutdown()
		Eventually(conn.Context().Done()).Should(BeClosed())
	})

	It("doesn't return a run error when closing", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			Expect(conn.run()).To(Succeed())
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		mconn.EXPECT().Write(gomock.Any(), gomock.Any())
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		conn.shutdown()
		Eventually(done).Should(BeClosed())
		Expect(context.Cause(conn.Context())).To(MatchError(context.Canceled))
	})

	It("passes errors to the connection runner", func() {
		testErr := errors.New("handshake error")
		expectedErr := &qerr.ApplicationError{
			ErrorCode:    0x1337,
			ErrorMessage: testErr.Error(),
		}
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			err := conn.run()
			Expect(err).To(MatchError(expectedErr))
			close(done)
		}()
		streamManager.EXPECT().CloseWithError(gomock.Any())
		expectReplaceWithClosed()
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		mconn.EXPECT().Write(gomock.Any(), gomock.Any())
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		Expect(conn.CloseWithError(0x1337, testErr.Error())).To(Succeed())
		Eventually(done).Should(BeClosed())
		Expect(context.Cause(conn.Context())).To(MatchError(expectedErr))
	})

	Context("transport parameters", func() {
		It("processes transport parameters received from the client", func() {
			params := &wire.TransportParameters{
				MaxIdleTimeout:                90 * time.Second,
				InitialMaxStreamDataBidiLocal: 0x5000,
				InitialMaxData:                0x5000,
				ActiveConnectionIDLimit:       3,
				// marshaling always sets it to this value
				MaxUDPPayloadSize:         protocol.MaxPacketBufferSize,
				InitialSourceConnectionID: destConnID,
			}
			streamManager.EXPECT().UpdateLimits(params)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).MaxTimes(3)
			Expect(conn.earlyConnReady()).ToNot(BeClosed())
			tracer.EXPECT().ReceivedTransportParameters(params)
			conn.handleTransportParameters(params)
			Expect(conn.earlyConnReady()).To(BeClosed())
		})
	})

	Context("keep-alives", func() {
		setRemoteIdleTimeout := func(t time.Duration) {
			streamManager.EXPECT().UpdateLimits(gomock.Any())
			tracer.EXPECT().ReceivedTransportParameters(gomock.Any())
			conn.handleTransportParameters(&wire.TransportParameters{
				MaxIdleTimeout:            t,
				InitialSourceConnectionID: destConnID,
			})
		}

		runConn := func() {
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
		}

		BeforeEach(func() {
			conn.config.MaxIdleTimeout = 30 * time.Second
			conn.config.KeepAlivePeriod = 15 * time.Second
			conn.receivedPacketHandler.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionHandshake, time.Now(), true)
		})

		AfterEach(func() {
			// make the go routine return
			expectReplaceWithClosed()
			streamManager.EXPECT().CloseWithError(gomock.Any())
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("sends a PING as a keep-alive after half the idle timeout", func() {
			setRemoteIdleTimeout(5 * time.Second)
			conn.lastPacketReceivedTime = time.Now().Add(-5 * time.Second / 2)
			sent := make(chan struct{})
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).Do(func(bool, protocol.ByteCount, protocol.VersionNumber) (*coalescedPacket, error) {
				close(sent)
				return nil, nil
			})
			runConn()
			Eventually(sent).Should(BeClosed())
		})

		It("sends a PING after a maximum of protocol.MaxKeepAliveInterval", func() {
			conn.config.MaxIdleTimeout = time.Hour
			setRemoteIdleTimeout(time.Hour)
			conn.lastPacketReceivedTime = time.Now().Add(-protocol.MaxKeepAliveInterval).Add(-time.Millisecond)
			sent := make(chan struct{})
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).Do(func(bool, protocol.ByteCount, protocol.VersionNumber) (*coalescedPacket, error) {
				close(sent)
				return nil, nil
			})
			runConn()
			Eventually(sent).Should(BeClosed())
		})

		It("doesn't send a PING packet if keep-alive is disabled", func() {
			setRemoteIdleTimeout(5 * time.Second)
			conn.config.KeepAlivePeriod = 0
			conn.lastPacketReceivedTime = time.Now().Add(-time.Second * 5 / 2)
			runConn()
			// don't EXPECT() any calls to mconn.Write()
			time.Sleep(50 * time.Millisecond)
		})

		It("doesn't send a PING if the handshake isn't completed yet", func() {
			conn.config.HandshakeIdleTimeout = time.Hour
			conn.handshakeComplete = false
			// Needs to be shorter than our idle timeout.
			// Otherwise we'll try to send a CONNECTION_CLOSE.
			conn.lastPacketReceivedTime = time.Now().Add(-20 * time.Second)
			runConn()
			// don't EXPECT() any calls to mconn.Write()
			time.Sleep(50 * time.Millisecond)
		})

		It("send PING as keep-alive earliest after 1.5 times the PTO", func() {
			conn.config.KeepAlivePeriod = time.Microsecond
			pto := conn.rttStats.PTO(true)
			conn.lastPacketReceivedTime = time.Now()
			sentPingTimeChan := make(chan time.Time)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).Do(func(bool, protocol.ByteCount, protocol.VersionNumber) (*coalescedPacket, error) {
				sentPingTimeChan <- time.Now()
				return nil, nil
			})
			runConn()
			sentPingTime := <-sentPingTimeChan
			Expect(sentPingTime.Sub(conn.lastPacketReceivedTime)).To(BeNumerically(">", pto*3/2))
		})
	})

	Context("timeouts", func() {
		BeforeEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		It("times out due to no network activity", func() {
			connRunner.EXPECT().Remove(gomock.Any()).Times(2)
			conn.lastPacketReceivedTime = time.Now().Add(-time.Hour)
			done := make(chan struct{})
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					Expect(e).To(MatchError(&qerr.IdleTimeoutError{}))
				}),
				tracer.EXPECT().Close(),
			)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				err := conn.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err).To(MatchError(qerr.ErrIdleTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("times out due to non-completed handshake", func() {
			conn.handshakeComplete = false
			conn.creationTime = time.Now().Add(-protocol.DefaultHandshakeTimeout).Add(-time.Second)
			connRunner.EXPECT().Remove(gomock.Any()).Times(2)
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					Expect(e).To(MatchError(&HandshakeTimeoutError{}))
				}),
				tracer.EXPECT().Close(),
			)
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				err := conn.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err).To(MatchError(qerr.ErrHandshakeTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("does not use the idle timeout before the handshake complete", func() {
			conn.handshakeComplete = false
			conn.config.HandshakeIdleTimeout = 9999 * time.Second
			conn.config.MaxIdleTimeout = 9999 * time.Second
			conn.lastPacketReceivedTime = time.Now().Add(-time.Minute)
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(e *qerr.ApplicationError, _ protocol.ByteCount, _ protocol.VersionNumber) (*coalescedPacket, error) {
				Expect(e.ErrorCode).To(BeZero())
				return &coalescedPacket{buffer: getPacketBuffer()}, nil
			})
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					idleTimeout := &IdleTimeoutError{}
					handshakeTimeout := &HandshakeTimeoutError{}
					Expect(errors.As(e, &idleTimeout)).To(BeFalse())
					Expect(errors.As(e, &handshakeTimeout)).To(BeFalse())
				}),
				tracer.EXPECT().Close(),
			)
			// the handshake timeout is irrelevant here, since it depends on the time the connection was created,
			// and not on the last network activity
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("closes the connection due to the idle timeout before handshake", func() {
			conn.config.HandshakeIdleTimeout = 0
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
			connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					Expect(e).To(MatchError(&IdleTimeoutError{}))
				}),
				tracer.EXPECT().Close(),
			)
			done := make(chan struct{})
			conn.handshakeComplete = false
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				cryptoSetup.EXPECT().GetSessionTicket().MaxTimes(1)
				err := conn.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err).To(MatchError(qerr.ErrIdleTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("closes the connection due to the idle timeout after handshake", func() {
			conn.sentPacketHandler.DropPackets(protocol.EncryptionInitial)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
			gomock.InOrder(
				connRunner.EXPECT().Retire(clientDestConnID),
				connRunner.EXPECT().Remove(gomock.Any()),
			)
			cryptoSetup.EXPECT().Close()
			gomock.InOrder(
				tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake),
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					Expect(e).To(MatchError(&IdleTimeoutError{}))
				}),
				tracer.EXPECT().Close(),
			)
			conn.idleTimeout = 0
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete})
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				cryptoSetup.EXPECT().GetSessionTicket().MaxTimes(1)
				cryptoSetup.EXPECT().SetHandshakeConfirmed().MaxTimes(1)
				Expect(conn.handleHandshakeComplete()).To(Succeed())
				err := conn.run()
				nerr, ok := err.(net.Error)
				Expect(ok).To(BeTrue())
				Expect(nerr.Timeout()).To(BeTrue())
				Expect(err).To(MatchError(qerr.ErrIdleTimeout))
				close(done)
			}()
			Eventually(done).Should(BeClosed())
		})

		It("doesn't time out when it just sent a packet", func() {
			conn.lastPacketReceivedTime = time.Now().Add(-time.Hour)
			conn.firstAckElicitingPacketAfterIdleSentTime = time.Now().Add(-time.Second)
			conn.idleTimeout = 30 * time.Second
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("times out earliest after 3 times the PTO", func() {
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).AnyTimes()
			connRunner.EXPECT().Retire(gomock.Any()).AnyTimes()
			connRunner.EXPECT().Remove(gomock.Any()).Times(2)
			cryptoSetup.EXPECT().Close()
			closeTimeChan := make(chan time.Time)
			tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
				Expect(e).To(MatchError(&IdleTimeoutError{}))
				closeTimeChan <- time.Now()
			})
			tracer.EXPECT().Close()
			conn.idleTimeout = time.Millisecond
			done := make(chan struct{})
			pto := conn.rttStats.PTO(true)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				cryptoSetup.EXPECT().GetSessionTicket().MaxTimes(1)
				cryptoSetup.EXPECT().SetHandshakeConfirmed().MaxTimes(1)
				conn.run()
				close(done)
			}()
			closeTime := <-closeTimeChan
			Expect(closeTime.Sub(conn.lastPacketReceivedTime)).To(BeNumerically(">", pto*3))
			Eventually(done).Should(BeClosed())
		})
	})

	It("stores up to MaxConnUnprocessedPackets packets", func() {
		done := make(chan struct{})
		tracer.EXPECT().DroppedPacket(logging.PacketTypeNotDetermined, logging.ByteCount(6), logging.PacketDropDOSPrevention).Do(func(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
			close(done)
		})
		// Nothing here should block
		for i := protocol.PacketNumber(0); i < protocol.MaxConnUnprocessedPackets+1; i++ {
			conn.handlePacket(receivedPacket{data: []byte("foobar")})
		}
		Eventually(done).Should(BeClosed())
	})

	Context("getting streams", func() {
		It("opens streams", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStream().Return(mstr, nil)
			str, err := conn.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens streams synchronously", func() {
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().OpenStreamSync(context.Background()).Return(mstr, nil)
			str, err := conn.OpenStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens unidirectional streams", func() {
			mstr := NewMockSendStreamI(mockCtrl)
			streamManager.EXPECT().OpenUniStream().Return(mstr, nil)
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("opens unidirectional streams synchronously", func() {
			mstr := NewMockSendStreamI(mockCtrl)
			streamManager.EXPECT().OpenUniStreamSync(context.Background()).Return(mstr, nil)
			str, err := conn.OpenUniStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts streams", func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			mstr := NewMockStreamI(mockCtrl)
			streamManager.EXPECT().AcceptStream(ctx).Return(mstr, nil)
			str, err := conn.AcceptStream(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})

		It("accepts unidirectional streams", func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			mstr := NewMockReceiveStreamI(mockCtrl)
			streamManager.EXPECT().AcceptUniStream(ctx).Return(mstr, nil)
			str, err := conn.AcceptUniStream(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(mstr))
		})
	})

	It("returns the local address", func() {
		Expect(conn.LocalAddr()).To(Equal(localAddr))
	})

	It("returns the remote address", func() {
		Expect(conn.RemoteAddr()).To(Equal(remoteAddr))
	})
})

var _ = Describe("Client Connection", func() {
	var (
		conn        *connection
		connRunner  *MockConnRunner
		packer      *MockPacker
		mconn       *MockSendConn
		cryptoSetup *mocks.MockCryptoSetup
		tracer      *mocklogging.MockConnectionTracer
		tlsConf     *tls.Config
		quicConf    *Config
	)
	srcConnID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	destConnID := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

	getPacket := func(hdr *wire.ExtendedHeader, data []byte) receivedPacket {
		b, err := hdr.Append(nil, conn.version)
		Expect(err).ToNot(HaveOccurred())
		return receivedPacket{
			rcvTime: time.Now(),
			data:    append(b, data...),
			buffer:  getPacketBuffer(),
		}
	}

	BeforeEach(func() {
		quicConf = populateConfig(&Config{})
		tlsConf = nil
	})

	JustBeforeEach(func() {
		Eventually(areConnsRunning).Should(BeFalse())

		mconn = NewMockSendConn(mockCtrl)
		mconn.EXPECT().capabilities().AnyTimes()
		mconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{}).AnyTimes()
		mconn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		mconn.EXPECT().capabilities().AnyTimes()
		if tlsConf == nil {
			tlsConf = &tls.Config{}
		}
		connRunner = NewMockConnRunner(mockCtrl)
		tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().SentTransportParameters(gomock.Any())
		tracer.EXPECT().UpdatedKeyFromTLS(gomock.Any(), gomock.Any()).AnyTimes()
		tracer.EXPECT().UpdatedCongestionState(gomock.Any())
		conn = newClientConnection(
			mconn,
			connRunner,
			destConnID,
			protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			&protocol.DefaultConnectionIDGenerator{},
			quicConf,
			tlsConf,
			42, // initial packet number
			false,
			false,
			tracer,
			1234,
			utils.DefaultLogger,
			protocol.Version1,
		).(*connection)
		packer = NewMockPacker(mockCtrl)
		conn.packer = packer
		cryptoSetup = mocks.NewMockCryptoSetup(mockCtrl)
		conn.cryptoStreamHandler = cryptoSetup
		conn.sentFirstPacket = true
	})

	It("changes the connection ID when receiving the first packet from the server", func() {
		unpacker := NewMockUnpacker(mockCtrl)
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(hdr *wire.Header, _ time.Time, data []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
			return &unpackedPacket{
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             &wire.ExtendedHeader{Header: *hdr},
				data:            []byte{0}, // one PADDING frame
			}, nil
		})
		conn.unpacker = unpacker
		done := make(chan struct{})
		packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(onlyAck bool, maxPacketSize protocol.ByteCount, v protocol.VersionNumber) { close(done) })
		newConnID := protocol.ParseConnectionID([]byte{1, 3, 3, 7, 1, 3, 3, 7})
		p := getPacket(&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             protocol.PacketTypeHandshake,
				SrcConnectionID:  newConnID,
				DestConnectionID: srcConnID,
				Length:           2 + 6,
				Version:          conn.version,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}, []byte("foobar"))
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), p.Size(), []logging.Frame{})
		Expect(conn.handlePacketImpl(p)).To(BeTrue())
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			conn.run()
		}()
		Eventually(done).Should(BeClosed())
		// make sure the go routine returns
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		connRunner.EXPECT().ReplaceWithClosed([]protocol.ConnectionID{srcConnID}, gomock.Any(), gomock.Any())
		mconn.EXPECT().Write(gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		conn.shutdown()
		Eventually(conn.Context().Done()).Should(BeClosed())
		time.Sleep(200 * time.Millisecond)
	})

	It("continues accepting Long Header packets after using a new connection ID", func() {
		unpacker := NewMockUnpacker(mockCtrl)
		conn.unpacker = unpacker
		connRunner.EXPECT().AddResetToken(gomock.Any(), gomock.Any())
		conn.connIDManager.SetHandshakeComplete()
		conn.handleNewConnectionIDFrame(&wire.NewConnectionIDFrame{
			SequenceNumber: 1,
			ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5}),
		})
		Expect(conn.connIDManager.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})))
		// now receive a packet with the original source connection ID
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).DoAndReturn(func(hdr *wire.Header, _ time.Time, _ []byte, _ protocol.VersionNumber) (*unpackedPacket, error) {
			return &unpackedPacket{
				hdr:             &wire.ExtendedHeader{Header: *hdr},
				data:            []byte{0},
				encryptionLevel: protocol.EncryptionHandshake,
			}, nil
		})
		hdr := &wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: srcConnID,
			SrcConnectionID:  destConnID,
		}
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any())
		Expect(conn.handleLongHeaderPacket(receivedPacket{buffer: getPacketBuffer()}, hdr)).To(BeTrue())
	})

	It("handles HANDSHAKE_DONE frames", func() {
		conn.peerParams = &wire.TransportParameters{}
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		conn.sentPacketHandler = sph
		tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake)
		sph.EXPECT().DropPackets(protocol.EncryptionHandshake)
		sph.EXPECT().SetHandshakeConfirmed()
		cryptoSetup.EXPECT().SetHandshakeConfirmed()
		Expect(conn.handleHandshakeDoneFrame()).To(Succeed())
	})

	It("interprets an ACK for 1-RTT packets as confirmation of the handshake", func() {
		conn.peerParams = &wire.TransportParameters{}
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		conn.sentPacketHandler = sph
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}}}
		tracer.EXPECT().DroppedEncryptionLevel(protocol.EncryptionHandshake)
		sph.EXPECT().ReceivedAck(ack, protocol.Encryption1RTT, gomock.Any()).Return(true, nil)
		sph.EXPECT().DropPackets(protocol.EncryptionHandshake)
		sph.EXPECT().SetHandshakeConfirmed()
		cryptoSetup.EXPECT().SetLargest1RTTAcked(protocol.PacketNumber(3))
		cryptoSetup.EXPECT().SetHandshakeConfirmed()
		Expect(conn.handleAckFrame(ack, protocol.Encryption1RTT)).To(Succeed())
	})

	It("doesn't send a CONNECTION_CLOSE when no packet was sent", func() {
		conn.sentFirstPacket = false
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		running := make(chan struct{})
		cryptoSetup.EXPECT().StartHandshake().Do(func() {
			close(running)
			conn.closeLocal(errors.New("early error"))
		})
		cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
		cryptoSetup.EXPECT().Close()
		connRunner.EXPECT().Remove(gomock.Any())
		go func() {
			defer GinkgoRecover()
			conn.run()
		}()
		Eventually(running).Should(BeClosed())
		Eventually(areConnsRunning).Should(BeFalse())
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
			Expect(conn.handleNewTokenFrame(&wire.NewTokenFrame{Token: []byte("foobar")})).To(Succeed())
		})
	})

	Context("handling Version Negotiation", func() {
		getVNP := func(versions ...protocol.VersionNumber) receivedPacket {
			b := wire.ComposeVersionNegotiation(
				protocol.ArbitraryLenConnectionID(srcConnID.Bytes()),
				protocol.ArbitraryLenConnectionID(destConnID.Bytes()),
				versions,
			)
			return receivedPacket{
				rcvTime: time.Now(),
				data:    b,
				buffer:  getPacketBuffer(),
			}
		}

		It("closes and returns the right error", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			conn.sentPacketHandler = sph
			sph.EXPECT().ReceivedBytes(gomock.Any())
			sph.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(128), protocol.PacketNumberLen4)
			conn.config.Versions = []protocol.VersionNumber{1234, 4321}
			errChan := make(chan error, 1)
			start := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().DoAndReturn(func() handshake.Event {
					<-start
					return handshake.Event{Kind: handshake.EventNoEvent}
				})
				errChan <- conn.run()
			}()
			connRunner.EXPECT().Remove(srcConnID)
			tracer.EXPECT().ReceivedVersionNegotiationPacket(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_, _ protocol.ArbitraryLenConnectionID, versions []logging.VersionNumber) {
				Expect(versions).To(And(
					ContainElement(protocol.VersionNumber(4321)),
					ContainElement(protocol.VersionNumber(1337)),
				))
			})
			cryptoSetup.EXPECT().Close()
			Expect(conn.handlePacketImpl(getVNP(4321, 1337))).To(BeFalse())
			close(start)
			var err error
			Eventually(errChan).Should(Receive(&err))
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&errCloseForRecreating{}))
			recreateErr := err.(*errCloseForRecreating)
			Expect(recreateErr.nextVersion).To(Equal(protocol.VersionNumber(4321)))
			Expect(recreateErr.nextPacketNumber).To(Equal(protocol.PacketNumber(128)))
		})

		It("it closes when no matching version is found", func() {
			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				errChan <- conn.run()
			}()
			connRunner.EXPECT().Remove(srcConnID).MaxTimes(1)
			packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
			gomock.InOrder(
				tracer.EXPECT().ReceivedVersionNegotiationPacket(gomock.Any(), gomock.Any(), gomock.Any()),
				tracer.EXPECT().ClosedConnection(gomock.Any()).Do(func(e error) {
					var vnErr *VersionNegotiationError
					Expect(errors.As(e, &vnErr)).To(BeTrue())
					Expect(vnErr.Theirs).To(ContainElement(logging.VersionNumber(12345678)))
				}),
				tracer.EXPECT().Close(),
			)
			cryptoSetup.EXPECT().Close()
			Expect(conn.handlePacketImpl(getVNP(12345678))).To(BeFalse())
			var err error
			Eventually(errChan).Should(Receive(&err))
			Expect(err).To(HaveOccurred())
			Expect(err).ToNot(BeAssignableToTypeOf(errCloseForRecreating{}))
			Expect(err.Error()).To(ContainSubstring("no compatible QUIC version found"))
		})

		It("ignores Version Negotiation packets that offer the current version", func() {
			p := getVNP(conn.version)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, p.Size(), logging.PacketDropUnexpectedVersion)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("ignores unparseable Version Negotiation packets", func() {
			p := getVNP(conn.version)
			p.data = p.data[:len(p.data)-2]
			tracer.EXPECT().DroppedPacket(logging.PacketTypeVersionNegotiation, p.Size(), logging.PacketDropHeaderParseError)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})
	})

	Context("handling Retry", func() {
		origDestConnID := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

		var retryHdr *wire.ExtendedHeader

		JustBeforeEach(func() {
			retryHdr = &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeRetry,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
					DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
					Token:            []byte("foobar"),
					Version:          conn.version,
				},
			}
		})

		getRetryTag := func(hdr *wire.ExtendedHeader) []byte {
			b, err := hdr.Append(nil, conn.version)
			Expect(err).ToNot(HaveOccurred())
			return handshake.GetRetryIntegrityTag(b, origDestConnID, hdr.Version)[:]
		}

		It("handles Retry packets", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			conn.sentPacketHandler = sph
			sph.EXPECT().ResetForRetry()
			sph.EXPECT().ReceivedBytes(gomock.Any())
			cryptoSetup.EXPECT().ChangeConnectionID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}))
			packer.EXPECT().SetToken([]byte("foobar"))
			tracer.EXPECT().ReceivedRetry(gomock.Any()).Do(func(hdr *wire.Header) {
				Expect(hdr.DestConnectionID).To(Equal(retryHdr.DestConnectionID))
				Expect(hdr.SrcConnectionID).To(Equal(retryHdr.SrcConnectionID))
				Expect(hdr.Token).To(Equal(retryHdr.Token))
			})
			Expect(conn.handlePacketImpl(getPacket(retryHdr, getRetryTag(retryHdr)))).To(BeTrue())
		})

		It("ignores Retry packets after receiving a regular packet", func() {
			conn.receivedFirstPacket = true
			p := getPacket(retryHdr, getRetryTag(retryHdr))
			tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, p.Size(), logging.PacketDropUnexpectedPacket)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("ignores Retry packets if the server didn't change the connection ID", func() {
			retryHdr.SrcConnectionID = destConnID
			p := getPacket(retryHdr, getRetryTag(retryHdr))
			tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, p.Size(), logging.PacketDropUnexpectedPacket)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		It("ignores Retry packets with the a wrong Integrity tag", func() {
			tag := getRetryTag(retryHdr)
			tag[0]++
			p := getPacket(retryHdr, tag)
			tracer.EXPECT().DroppedPacket(logging.PacketTypeRetry, p.Size(), logging.PacketDropPayloadDecryptError)
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})
	})

	Context("transport parameters", func() {
		var (
			closed     bool
			errChan    chan error
			paramsChan chan *wire.TransportParameters
		)

		JustBeforeEach(func() {
			errChan = make(chan error, 1)
			paramsChan = make(chan *wire.TransportParameters, 1)
			closed = false
			packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake().MaxTimes(1)
				// This is not 100% what would happen in reality.
				// The run loop calls NextEvent once when it starts up (to send out the ClientHello),
				// and then again every time a CRYPTO frame is handled.
				// Injecting a CRYPTO frame is not straightforward though,
				// so we inject the transport parameters on the first call to NextEvent.
				params := <-paramsChan
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{
					Kind:                handshake.EventReceivedTransportParameters,
					TransportParameters: params,
				})
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}).MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}).MaxTimes(1).Do(func() {
					defer GinkgoRecover()
					Expect(conn.handleHandshakeComplete()).To(Succeed())
				})
				errChan <- conn.run()
				close(errChan)
			}()
		})

		expectClose := func(applicationClose, errored bool) {
			if !closed && !errored {
				connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())
				if applicationClose {
					packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil).MaxTimes(1)
				} else {
					packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil).MaxTimes(1)
				}
				cryptoSetup.EXPECT().Close()
				mconn.EXPECT().Write(gomock.Any(), gomock.Any())
				gomock.InOrder(
					tracer.EXPECT().ClosedConnection(gomock.Any()),
					tracer.EXPECT().Close(),
				)
			}
			closed = true
		}

		AfterEach(func() {
			conn.shutdown()
			Eventually(conn.Context().Done()).Should(BeClosed())
			Eventually(errChan).Should(BeClosed())
		})

		It("uses the preferred_address connection ID", func() {
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				PreferredAddress: &wire.PreferredAddress{
					IPv4:                net.IPv4(127, 0, 0, 1),
					IPv6:                net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
					StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
				},
			}
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), conn.version).MaxTimes(1)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			// make sure the connection ID is not retired
			cf, _ := conn.framer.AppendControlFrames(nil, protocol.MaxByteCount, protocol.Version1)
			Expect(cf).To(BeEmpty())
			connRunner.EXPECT().AddResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}, conn)
			Expect(conn.connIDManager.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
			// shut down
			connRunner.EXPECT().RemoveResetToken(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
			expectClose(true, false)
		})

		It("uses the minimum of the peers' idle timeouts", func() {
			conn.config.MaxIdleTimeout = 19 * time.Second
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				MaxIdleTimeout:                  18 * time.Second,
			}
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			// close first
			expectClose(true, false)
			conn.shutdown()
			// then check. Avoids race condition when accessing idleTimeout
			Expect(conn.idleTimeout).To(Equal(18 * time.Second))
		})

		It("errors if the transport parameters contain a wrong initial_source_connection_id", func() {
			conn.handshakeDestConnID = protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
				StatelessResetToken:             &protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "expected initial_source_connection_id to equal deadbeef, is decafbad",
			})))
		})

		It("errors if the transport parameters don't contain the retry_source_connection_id, if a Retry was performed", func() {
			rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
			conn.retrySrcConnID = &rcid
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				StatelessResetToken:             &protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "missing retry_source_connection_id",
			})))
		})

		It("errors if the transport parameters contain the wrong retry_source_connection_id, if a Retry was performed", func() {
			rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
			rcid2 := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
			conn.retrySrcConnID = &rcid
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				RetrySourceConnectionID:         &rcid2,
				StatelessResetToken:             &protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "expected retry_source_connection_id to equal deadbeef, is deadc0de",
			})))
		})

		It("errors if the transport parameters contain the retry_source_connection_id, if no Retry was performed", func() {
			rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				RetrySourceConnectionID:         &rcid,
				StatelessResetToken:             &protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "received retry_source_connection_id, although no Retry was performed",
			})))
		})

		It("errors if the transport parameters contain a wrong original_destination_connection_id", func() {
			conn.origDestConnID = protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
				InitialSourceConnectionID:       conn.handshakeDestConnID,
				StatelessResetToken:             &protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.TransportParameterError,
				ErrorMessage: "expected original_destination_connection_id to equal deadbeef, is decafbad",
			})))
		})

		It("errors if the transport parameters contain reduced limits after knowing 0-RTT data is accepted by the server", func() {
			conn.perspective = protocol.PerspectiveClient
			conn.peerParams = &wire.TransportParameters{
				ActiveConnectionIDLimit:        3,
				InitialMaxData:                 0x5000,
				InitialMaxStreamDataBidiLocal:  0x5000,
				InitialMaxStreamDataBidiRemote: 1000,
				InitialMaxStreamDataUni:        1000,
				MaxBidiStreamNum:               500,
				MaxUniStreamNum:                500,
			}
			params := &wire.TransportParameters{
				OriginalDestinationConnectionID: destConnID,
				InitialSourceConnectionID:       destConnID,
				ActiveConnectionIDLimit:         3,
				InitialMaxData:                  0x5000,
				InitialMaxStreamDataBidiLocal:   0x5000,
				InitialMaxStreamDataBidiRemote:  1000,
				InitialMaxStreamDataUni:         1000,
				MaxBidiStreamNum:                300,
				MaxUniStreamNum:                 300,
			}
			expectClose(false, true)
			processed := make(chan struct{})
			tracer.EXPECT().ReceivedTransportParameters(params).Do(func(*wire.TransportParameters) { close(processed) })
			cryptoSetup.EXPECT().ConnectionState().Return(handshake.ConnectionState{Used0RTT: true})
			paramsChan <- params
			Eventually(processed).Should(BeClosed())
			Eventually(errChan).Should(Receive(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "server sent reduced limits after accepting 0-RTT data",
			})))
		})
	})

	Context("handling potentially injected packets", func() {
		var unpacker *MockUnpacker

		getPacket := func(extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
			b, err := extHdr.Append(nil, conn.version)
			Expect(err).ToNot(HaveOccurred())
			return receivedPacket{
				data:   append(b, data...),
				buffer: getPacketBuffer(),
			}
		}

		// Convert an already packed raw packet into a receivedPacket
		wrapPacket := func(packet []byte) receivedPacket {
			return receivedPacket{
				data:   packet,
				buffer: getPacketBuffer(),
			}
		}

		// Illustrates that attacker may inject an Initial packet with a different
		// source connection ID, causing endpoint to ignore a subsequent real Initial packets.
		It("ignores Initial packets with a different source connection ID", func() {
			// Modified from test "ignores packets with a different source connection ID"
			unpacker = NewMockUnpacker(mockCtrl)
			conn.unpacker = unpacker

			hdr1 := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  srcConnID,
					Length:           1,
					Version:          conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    1,
			}
			hdr2 := &wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: destConnID,
					SrcConnectionID:  protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
					Length:           1,
					Version:          conn.version,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
				PacketNumber:    2,
			}
			Expect(hdr2.SrcConnectionID).ToNot(Equal(srcConnID))
			// Send one packet, which might change the connection ID.
			// only EXPECT one call to the unpacker
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(&unpackedPacket{
				encryptionLevel: protocol.EncryptionInitial,
				hdr:             hdr1,
				data:            []byte{0}, // one PADDING frame
			}, nil)
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any())
			Expect(conn.handlePacketImpl(getPacket(hdr1, nil))).To(BeTrue())
			// The next packet has to be ignored, since the source connection ID doesn't match.
			tracer.EXPECT().DroppedPacket(gomock.Any(), gomock.Any(), gomock.Any())
			Expect(conn.handlePacketImpl(getPacket(hdr2, nil))).To(BeFalse())
		})

		It("ignores 0-RTT packets", func() {
			p := getPacket(&wire.ExtendedHeader{
				Header: wire.Header{
					Type:             protocol.PacketType0RTT,
					DestConnectionID: srcConnID,
					Length:           2 + 6,
					Version:          conn.version,
				},
				PacketNumber:    0x42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}, []byte("foobar"))
			tracer.EXPECT().DroppedPacket(logging.PacketType0RTT, p.Size(), gomock.Any())
			Expect(conn.handlePacketImpl(p)).To(BeFalse())
		})

		// Illustrates that an injected Initial with an ACK frame for an unsent packet causes
		// the connection to immediately break down
		It("fails on Initial-level ACK for unsent packet", func() {
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			initialPacket := testutils.ComposeInitialPacket(destConnID, srcConnID, conn.version, destConnID, []wire.Frame{ack})
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any())
			Expect(conn.handlePacketImpl(wrapPacket(initialPacket))).To(BeFalse())
		})

		// Illustrates that an injected Initial with a CONNECTION_CLOSE frame causes
		// the connection to immediately break down
		It("fails on Initial-level CONNECTION_CLOSE frame", func() {
			connCloseFrame := &wire.ConnectionCloseFrame{
				IsApplicationError: true,
				ReasonPhrase:       "mitm attacker",
			}
			initialPacket := testutils.ComposeInitialPacket(destConnID, srcConnID, conn.version, destConnID, []wire.Frame{connCloseFrame})
			tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any())
			Expect(conn.handlePacketImpl(wrapPacket(initialPacket))).To(BeTrue())
		})

		// Illustrates that attacker who injects a Retry packet and changes the connection ID
		// can cause subsequent real Initial packets to be ignored
		It("ignores Initial packets which use original source id, after accepting a Retry", func() {
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			conn.sentPacketHandler = sph
			sph.EXPECT().ReceivedBytes(gomock.Any()).Times(2)
			sph.EXPECT().ResetForRetry()
			newSrcConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
			cryptoSetup.EXPECT().ChangeConnectionID(newSrcConnID)
			packer.EXPECT().SetToken([]byte("foobar"))

			tracer.EXPECT().ReceivedRetry(gomock.Any())
			conn.handlePacketImpl(wrapPacket(testutils.ComposeRetryPacket(newSrcConnID, destConnID, destConnID, []byte("foobar"), conn.version)))
			initialPacket := testutils.ComposeInitialPacket(conn.connIDManager.Get(), srcConnID, conn.version, conn.connIDManager.Get(), nil)
			tracer.EXPECT().DroppedPacket(gomock.Any(), gomock.Any(), gomock.Any())
			Expect(conn.handlePacketImpl(wrapPacket(initialPacket))).To(BeFalse())
		})
	})
})
