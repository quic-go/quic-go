package quic

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/lucas-clemente/quic-go/utils"
)

type mockConnection struct {
	written [][]byte
}

func (m *mockConnection) write(p []byte) error {
	m.written = append(m.written, p)
	return nil
}

func (*mockConnection) setCurrentRemoteAddr(addr interface{}) {}

type mockCongestion struct {
	nCalls                int
	argsOnPacketSent      []interface{}
	argsOnCongestionEvent []interface{}
}

func (m *mockCongestion) TimeUntilSend(now time.Time, bytesInFlight protocol.ByteCount) time.Duration {
	panic("not implemented")
}

func (m *mockCongestion) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) bool {
	m.nCalls++
	m.argsOnPacketSent = []interface{}{sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable}
	return false
}

func (m *mockCongestion) GetCongestionWindow() protocol.ByteCount {
	m.nCalls++
	return protocol.DefaultTCPMSS
}

func (m *mockCongestion) OnCongestionEvent(rttUpdated bool, bytesInFlight protocol.ByteCount, ackedPackets congestion.PacketVector, lostPackets congestion.PacketVector) {
	m.nCalls++
	m.argsOnCongestionEvent = []interface{}{rttUpdated, bytesInFlight, ackedPackets, lostPackets}
}

func (m *mockCongestion) SetNumEmulatedConnections(n int) {
	panic("not implemented")
}

func (m *mockCongestion) OnRetransmissionTimeout(packetsRetransmitted bool) {
	panic("not implemented")
}

func (m *mockCongestion) OnConnectionMigration() {
	panic("not implemented")
}

func (m *mockCongestion) RetransmissionDelay() time.Duration {
	panic("not implemented")
}

func (m *mockCongestion) SetSlowStartLargeReduction(enabled bool) {
	panic("not implemented")
}

// TODO: Reorganize
var _ = Describe("Session", func() {
	var (
		session        *Session
		callbackCalled bool
		conn           *mockConnection
	)

	BeforeEach(func() {
		conn = &mockConnection{}
		callbackCalled = false
		session = &Session{
			conn:                        conn,
			streams:                     make(map[protocol.StreamID]*stream),
			streamCallback:              func(*Session, utils.Stream) { callbackCalled = true },
			connectionParametersManager: handshake.NewConnectionParamatersManager(),
			closeChan:                   make(chan struct{}, 1),
			closeCallback:               func(protocol.ConnectionID) {},
			packer:                      &packetPacker{aead: &crypto.NullAEAD{}},
		}
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("rejects streams with even StreamIDs", func() {
			err := session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 4,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(errInvalidStreamID))
		})

		It("does not reject existing streams with even StreamIDs", func() {
			_, err := session.NewStream(4)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 4,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("handles existing streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(callbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not delete streams with Close()", func() {
			str, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
		})

		It("does not delete streams with FIN bit", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(Equal(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
		})

		It("closes streams with FIN bit & close", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(Equal(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			// We still need to close the stream locally
			session.streams[5].Close()
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = session.streams[5].Read(p)
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes empty streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
			})
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(callbackCalled).To(BeTrue())
			session.closeStreamsWithError(testErr)
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(1))
			Expect(session.streams[5]).To(BeNil())
		})

		It("rejects streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(Equal(io.EOF))
			session.streams[5].Close()
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(errReopeningStreamsNotAllowed))
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the receiving streams for writing and reading", func() {
			s, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).ToNot(HaveOccurred())
			n, err := s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
			n, err = s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError("RST_STREAM received with code 42"))
		})

		It("errors when the stream is not known", func() {
			err := session.handleRstStreamFrame(&frames.RstStreamFrame{
				StreamID:  5,
				ErrorCode: 42,
			})
			Expect(err).To(MatchError(errRstStreamOnInvalidStream))
		})
	})

	Context("handling WINDOW_UPDATE frames", func() {
		It("updates the Flow Control Windows of a stream", func() {
			_, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 0x8000,
			})
			Expect(err).ToNot(HaveOccurred())
		})

		It("errors when the stream is not known", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnInvalidStream))
		})
	})

	Context("closing", func() {
		var (
			nGoRoutinesBefore int
			closed            bool
		)

		BeforeEach(func() {
			time.Sleep(10 * time.Millisecond) // Wait for old goroutines to finish
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			nGoRoutinesBefore = runtime.NumGoroutine()
			session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) { closed = true }).(*Session)
			go session.Run()
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore + 2))
		})

		It("shuts down without error", func() {
			session.Close(nil, true)
			Expect(closed).To(BeTrue())
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := session.NewStream(5)
			Expect(err).NotTo(HaveOccurred())
			session.Close(testErr, true)
			Expect(closed).To(BeTrue())
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(Equal(testErr))
		})
	})

	Context("sending packets", func() {
		BeforeEach(func() {
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, nil).(*Session)
		})

		It("sends ack frames", func() {
			packetNumber := protocol.PacketNumber(0x0135)
			var entropy ackhandler.EntropyAccumulator
			session.receivedPacketHandler.ReceivedPacket(packetNumber, true)
			entropy.Add(packetNumber, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			// test for the beginning of an ACK frame: Entropy until LargestObserved
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{byte(entropy), 0x35, 0x01})))
		})

		It("sends queued stream frames", func() {
			session.QueueStreamFrame(&frames.StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			})
			session.receivedPacketHandler.ReceivedPacket(1, true)
			err := session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			// test for the beginning of an ACK frame: TypeByte until LargestObserved
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x40, 0x2, 0x1})))
			Expect(conn.written[0]).To(ContainSubstring(string("foobar")))
		})

		It("sends a WindowUpdate frame", func() {
			_, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.UpdateReceiveFlowControlWindow(5, 0xDECAFBAD)
			Expect(err).ToNot(HaveOccurred())
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
		})

		It("repeats a WindowUpdate frame in WindowUpdateNumRepitions packets", func() {
			_, err := session.NewStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.UpdateReceiveFlowControlWindow(5, 0xDECAFBAD)
			Expect(err).ToNot(HaveOccurred())
			for i := uint8(0); i < protocol.WindowUpdateNumRepitions; i++ {
				err = session.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(conn.written[i]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
			}
			Expect(conn.written).To(HaveLen(int(protocol.WindowUpdateNumRepitions)))
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(int(protocol.WindowUpdateNumRepitions))) // no packet was sent
		})

		It("sends public reset", func() {
			err := session.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		})
	})

	Context("scheduling sending", func() {
		BeforeEach(func() {
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) {}).(*Session)
		})

		It("sends after queuing a stream frame", func() {
			Expect(session.sendingScheduled).NotTo(Receive())
			err := session.QueueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			// Try again, so that we detect blocking scheduleSending
			err = session.QueueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.sendingScheduled).To(Receive())
		})

		It("sends after receiving a packet", func() {
			Expect(session.sendingScheduled).NotTo(Receive())
			session.receivedPackets <- receivedPacket{
				publicHeader: &PublicHeader{},
				data: []byte{
					// FNV hash + "foobar"
					0x18, 0x6f, 0x44, 0xba, 0x97, 0x35, 0xd, 0x6f, 0xbf, 0x64, 0x3c, 0x79, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72,
				},
			}
			session.Run()
			Expect(session.sendingScheduled).To(Receive())
		})

		Context("bundling of small packets", func() {
			It("bundles two small frames into one packet", func() {
				go session.Run()

				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar2"),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(1))
			})

			It("sends out two big frames in two packet", func() {
				go session.Run()

				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     bytes.Repeat([]byte{'e'}, int(protocol.SmallPacketPayloadSizeThreshold+50)),
				})
				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     bytes.Repeat([]byte{'f'}, int(protocol.SmallPacketPayloadSizeThreshold+50)),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(2))
			})

			It("sends out two small frames that are written to long after one another into two packet", func() {
				go session.Run()

				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				time.Sleep(10 * protocol.SmallPacketSendDelay)
				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar2"),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(2))
			})

			It("sends a queued ACK frame only once", func() {
				go session.Run()

				packetNumber := protocol.PacketNumber(0x1337)
				session.receivedPacketHandler.ReceivedPacket(packetNumber, true)
				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				time.Sleep(10 * protocol.SmallPacketSendDelay)
				session.QueueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar2"),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(2))
				Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x37, 0x13})))
				Expect(conn.written[1]).ToNot(ContainSubstring(string([]byte{0x37, 0x13})))
			})
		})
	})

	It("closes when crypto stream errors", func() {
		signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
		session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) {}).(*Session)
		s, err := session.NewStream(3)
		Expect(err).NotTo(HaveOccurred())
		err = session.handleStreamFrame(&frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("4242\x00\x00\x00\x00"),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool { return session.closed }).Should(BeTrue())
		_, err = s.Write([]byte{})
		Expect(err).To(MatchError("CryptoSetup: expected CHLO"))
	})

	It("sends public reset after too many undecryptable packets", func() {
		signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
		session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) {}).(*Session)

		// Write protocol.MaxUndecryptablePackets and expect a public reset to happen
		for i := 0; i < protocol.MaxUndecryptablePackets; i++ {
			hdr := &PublicHeader{
				PacketNumber: protocol.PacketNumber(i + 1),
			}
			session.HandlePacket(nil, hdr, []byte("foobar"))
		}
		session.Run()

		Expect(conn.written).To(HaveLen(1))
		Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
	})

	It("unqueues undecryptable packets for later decryption", func() {
		signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
		session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) {}).(*Session)
		session.undecryptablePackets = []receivedPacket{{
			nil,
			&PublicHeader{PacketNumber: protocol.PacketNumber(42)},
			nil,
		}}
		Expect(session.receivedPackets).NotTo(Receive())
		session.tryDecryptingQueuedPackets()
		Expect(session.undecryptablePackets).To(BeEmpty())
		Expect(session.receivedPackets).To(Receive())
	})

	It("times out", func(done Done) {
		session.connectionParametersManager.SetFromMap(map[handshake.Tag][]byte{
			handshake.TagICSL: {0, 0, 0, 0},
		})
		session.packer.connectionParametersManager = session.connectionParametersManager
		session.packer.sentPacketHandler = newMockSentPacketHandler()
		session.Run() // Would normally not return
		Expect(conn.written[0]).To(ContainSubstring("No recent network activity."))
		close(done)
	}, 0.5)

	Context("congestion", func() {
		var (
			cong *mockCongestion
		)

		BeforeEach(func() {
			signer, err := crypto.NewRSASigner(testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			scfg := handshake.NewServerConfig(crypto.NewCurve25519KEX(), signer)
			session = NewSession(conn, 0, 0, scfg, nil, func(protocol.ConnectionID) {}).(*Session)

			cong = &mockCongestion{}
			session.congestion = cong
		})

		It("should call OnSent", func() {
			session.QueueStreamFrame(&frames.StreamFrame{StreamID: 5})
			session.sendPacket()
			Expect(cong.nCalls).To(Equal(2)) // OnPacketSent + GetCongestionWindow
			Expect(cong.argsOnPacketSent[1]).To(Equal(protocol.ByteCount(25)))
			Expect(cong.argsOnPacketSent[2]).To(Equal(protocol.PacketNumber(1)))
			Expect(cong.argsOnPacketSent[3]).To(Equal(protocol.ByteCount(25)))
			Expect(cong.argsOnPacketSent[4]).To(BeTrue())
		})

		It("should call OnCongestionEvent", func() {
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 1, Frames: []frames.Frame{}, Length: 1})
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 2, Frames: []frames.Frame{}, Length: 2})
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 3, Frames: []frames.Frame{}, Length: 3})
			err := session.handleAckFrame(&frames.AckFrame{
				LargestObserved: 3,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(cong.nCalls).To(Equal(1))
			//(rttUpdated bool, bytesInFlight protocol.ByteCount, ackedPackets cong.PacketVector, lostPackets cong.PacketVector)
			Expect(cong.argsOnCongestionEvent[0]).To(BeTrue())
			Expect(cong.argsOnCongestionEvent[1]).To(Equal(protocol.ByteCount(2)))
			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{1, 1}, {3, 3}}))
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{}))

			// Loose the packet
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 4, Frames: []frames.Frame{}, Length: 4})
			err = session.handleAckFrame(&frames.AckFrame{
				LargestObserved: 4,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 5, Frames: []frames.Frame{}, Length: 5})
			err = session.handleAckFrame(&frames.AckFrame{
				LargestObserved: 5,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())
			session.sentPacketHandler.SentPacket(&ackhandler.Packet{PacketNumber: 6, Frames: []frames.Frame{}, Length: 6})
			err = session.handleAckFrame(&frames.AckFrame{
				LargestObserved: 6,
				NackRanges:      []frames.NackRange{{2, 2}},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(cong.argsOnCongestionEvent[2]).To(Equal(congestion.PacketVector{{6, 6}}))
			Expect(cong.argsOnCongestionEvent[3]).To(Equal(congestion.PacketVector{{2, 2}}))
		})
	})
})
