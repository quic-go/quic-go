package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

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

	expectReplaceWithClosed := func() {
		connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any()).Do(func(connIDs []protocol.ConnectionID, _ []byte) {
			Expect(connIDs).To(ContainElement(srcConnID))
			if len(connIDs) > 1 {
				Expect(connIDs).To(ContainElement(clientDestConnID))
			}
		})
	}

	expectAppendPacket := func(packer *MockPacker, p shortHeaderPacket, b []byte) *MockPackerAppendPacketCall {
		return packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), Version1).DoAndReturn(func(buf *packetBuffer, _ protocol.ByteCount, _ time.Time, _ protocol.Version) (shortHeaderPacket, error) {
			buf.Data = append(buf.Data, b...)
			return p, nil
		})
	}

	BeforeEach(func() {
		Eventually(areConnsRunning).Should(BeFalse())

		connRunner = NewMockConnRunner(mockCtrl)
		mconn = NewMockSendConn(mockCtrl)
		mconn.EXPECT().capabilities().DoAndReturn(func() connCapabilities { return capabilities }).AnyTimes()
		mconn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
		mconn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
		tokenGenerator := handshake.NewTokenGenerator([32]byte{0xa, 0xb, 0xc})
		var tr *logging.ConnectionTracer
		tr, tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().SentTransportParameters(gomock.Any())
		tracer.EXPECT().UpdatedKeyFromTLS(gomock.Any(), gomock.Any()).AnyTimes()
		tracer.EXPECT().UpdatedCongestionState(gomock.Any())
		ctx, cancel := context.WithCancelCause(context.Background())
		conn = newConnection(
			ctx,
			cancel,
			mconn,
			connRunner,
			protocol.ConnectionID{},
			nil,
			clientDestConnID,
			destConnID,
			srcConnID,
			&protocol.DefaultConnectionIDGenerator{},
			protocol.StatelessResetToken{},
			populateConfig(&Config{DisablePathMTUDiscovery: true}),
			&tls.Config{},
			tokenGenerator,
			false,
			tr,
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

		It("handles NEW_CONNECTION_ID frames", func() {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
			Expect(conn.handleFrame(&wire.NewConnectionIDFrame{
				SequenceNumber: 10,
				ConnectionID:   connID,
			}, protocol.Encryption1RTT, protocol.ConnectionID{}, time.Now())).To(Succeed())
			Expect(conn.connIDManager.queue.Back().Value.ConnectionID).To(Equal(connID))
		})

		It("handles PING frames", func() {
			err := conn.handleFrame(&wire.PingFrame{}, protocol.Encryption1RTT, protocol.ConnectionID{}, time.Now())
			Expect(err).NotTo(HaveOccurred())
		})

		It("handles PATH_CHALLENGE frames", func() {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			err := conn.handleFrame(&wire.PathChallengeFrame{Data: data}, protocol.Encryption1RTT, protocol.ConnectionID{}, time.Now())
			Expect(err).ToNot(HaveOccurred())
			frames, _ := conn.framer.AppendControlFrames(nil, 1000, time.Now(), protocol.Version1)
			Expect(frames).To(Equal([]ackhandler.Frame{{Frame: &wire.PathResponseFrame{Data: data}}}))
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

		It("processes multiple received packets before sending one", func() {
			conn.creationTime = time.Now()
			var pn protocol.PacketNumber
			unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				pn++
				return pn, protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* PADDING frame */, nil
			}).Times(3)
			tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), conn.version) // only expect a single call

			for i := 0; i < 3; i++ {
				conn.handlePacket(getShortHeaderPacket(srcConnID, 0x1337+protocol.PacketNumber(i), []byte("foobar")))
			}

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
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
			mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
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
			tracer.EXPECT().ReceivedShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), conn.version).Times(3)

			for i := 0; i < 3; i++ {
				conn.handlePacket(getShortHeaderPacket(srcConnID, 0x1337+protocol.PacketNumber(i), []byte("foobar")))
			}

			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
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
			mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
			conn.closeLocal(errors.New("close"))
			Eventually(conn.Context().Done()).Should(BeClosed())
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
			unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(nil, handshake.ErrKeysNotYetAvailable)
			packet := getLongHeaderPacket(hdr, nil)
			tracer.EXPECT().BufferedPacket(logging.PacketTypeHandshake, packet.Size())
			Expect(conn.handlePacketImpl(packet)).To(BeFalse())
			Expect(conn.undecryptablePackets).To(Equal([]receivedPacket{packet}))
		})
	})

	Context("packet pacing", func() {
		var (
			sph    *mockackhandler.MockSentPacketHandler
			sender *MockSender
		)

		BeforeEach(func() {
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
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
			sph.EXPECT().ECNMode(gomock.Any()).MaxTimes(1)
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			sender.EXPECT().Close()
			conn.CloseWithError(0, "")
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("stops sending when there are new packets to receive", func() {
			sender.EXPECT().WouldBlock().AnyTimes()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()

			written := make(chan struct{})
			sender.EXPECT().WouldBlock().AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(time.Time, protocol.PacketNumber, protocol.PacketNumber, []ackhandler.StreamFrame, []ackhandler.Frame, protocol.EncryptionLevel, protocol.ECN, protocol.ByteCount, bool) {
				sph.EXPECT().ReceivedBytes(gomock.Any())
				conn.handlePacket(receivedPacket{buffer: getPacketBuffer()})
			})
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 10}, []byte("packet10"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(*packetBuffer, uint16, protocol.ECN) { close(written) })

			conn.scheduleSending()
			time.Sleep(scaleDuration(50 * time.Millisecond))

			Eventually(written).Should(BeClosed())
		})

		It("doesn't set a pacing timer when there is no data to send", func() {
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
			sender.EXPECT().WouldBlock().AnyTimes()
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			// don't EXPECT any calls to mconn.Write()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			conn.scheduleSending() // no packet will get sent
			time.Sleep(50 * time.Millisecond)
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
			mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
			sender.EXPECT().Close()
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.CloseWithError(0, "")
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("sets the timer to the ack timer", func() {
			expectAppendPacket(packer, shortHeaderPacket{PacketNumber: 1234}, []byte("packet1234"))
			packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), conn.version).Return(shortHeaderPacket{}, errNothingToPack)
			sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
			sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
			sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
			sph.EXPECT().ECNMode(gomock.Any()).AnyTimes()
			sph.EXPECT().SentPacket(gomock.Any(), protocol.PacketNumber(1234), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
			conn.sentPacketHandler = sph
			rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
			rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(10 * time.Millisecond))
			// make the run loop wait
			rph.EXPECT().GetAlarmTimeout().Return(time.Now().Add(time.Hour)).MaxTimes(1)
			conn.receivedPacketHandler = rph

			written := make(chan struct{})
			sender.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(*packetBuffer, uint16, protocol.ECN) { close(written) })
			tracer.EXPECT().SentShortHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Eventually(written).Should(BeClosed())
		})
	})

	Context("timeouts", func() {
		BeforeEach(func() {
			streamManager.EXPECT().CloseWithError(gomock.Any())
		})

		It("doesn't time out when it just sent a packet", func() {
			conn.lastPacketReceivedTime = time.Now().Add(-time.Hour)
			conn.firstAckElicitingPacketAfterIdleSentTime = time.Now().Add(-time.Second)
			conn.idleTimeout = 30 * time.Second
			go func() {
				defer GinkgoRecover()
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
				cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
				conn.run()
			}()
			Consistently(conn.Context().Done()).ShouldNot(BeClosed())
			// make the go routine return
			packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
			expectReplaceWithClosed()
			cryptoSetup.EXPECT().Close()
			mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
			tracer.EXPECT().ClosedConnection(gomock.Any())
			tracer.EXPECT().Close()
			conn.CloseWithError(0, "")
			Eventually(conn.Context().Done()).Should(BeClosed())
		})

		It("times out earliest after 3 times the PTO", func() {
			packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), conn.version).AnyTimes()
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
				cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
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
		var tr *logging.ConnectionTracer
		tr, tracer = mocklogging.NewMockConnectionTracer(mockCtrl)
		tracer.EXPECT().NegotiatedVersion(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().SentTransportParameters(gomock.Any())
		tracer.EXPECT().UpdatedKeyFromTLS(gomock.Any(), gomock.Any()).AnyTimes()
		tracer.EXPECT().UpdatedCongestionState(gomock.Any())
		conn = newClientConnection(
			context.Background(),
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
			tr,
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
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
			return &unpackedPacket{
				encryptionLevel: protocol.Encryption1RTT,
				hdr:             &wire.ExtendedHeader{Header: *hdr},
				data:            []byte{0}, // one PADDING frame
			}, nil
		})
		conn.unpacker = unpacker
		done := make(chan struct{})
		packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Do(func(bool, protocol.ByteCount, time.Time, protocol.Version) (*coalescedPacket, error) {
			close(done)
			return nil, nil
		})
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
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), p.Size(), gomock.Any(), []logging.Frame{})
		Expect(conn.handlePacketImpl(p)).To(BeTrue())
		go func() {
			defer GinkgoRecover()
			cryptoSetup.EXPECT().StartHandshake(gomock.Any()).MaxTimes(1)
			cryptoSetup.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent})
			conn.run()
		}()
		Eventually(done).Should(BeClosed())
		// make sure the go routine returns
		packer.EXPECT().PackApplicationClose(gomock.Any(), gomock.Any(), conn.version).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
		cryptoSetup.EXPECT().Close()
		connRunner.EXPECT().ReplaceWithClosed([]protocol.ConnectionID{srcConnID}, gomock.Any())
		mconn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
		tracer.EXPECT().ClosedConnection(gomock.Any())
		tracer.EXPECT().Close()
		conn.CloseWithError(0, "")
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
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).DoAndReturn(func(hdr *wire.Header, _ []byte) (*unpackedPacket, error) {
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
		tracer.EXPECT().ReceivedLongHeaderPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		Expect(conn.handleLongHeaderPacket(receivedPacket{buffer: getPacketBuffer()}, hdr)).To(BeTrue())
	})
})
