package quic

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"time"

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
	written [][]byte
}

func (m *mockConnection) write(p []byte) error {
	m.written = append(m.written, p)
	return nil
}

func (*mockConnection) setCurrentRemoteAddr(addr interface{}) {}
func (*mockConnection) IP() net.IP                            { return nil }

var _ = Describe("Session", func() {
	var (
		session              *Session
		streamCallbackCalled bool
		closeCallbackCalled  bool
		conn                 *mockConnection
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
			0,
			0,
			scfg,
			func(*Session, utils.Stream) { streamCallbackCalled = true },
			func(protocol.ConnectionID) { closeCallbackCalled = true },
		)
		Expect(err).NotTo(HaveOccurred())
		session = pSession.(*Session)
		Expect(session.streams).To(HaveLen(1)) // Crypto stream
	})

	Context("when handling stream frames", func() {
		It("makes new streams", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(2))
			Expect(streamCallbackCalled).To(BeTrue())
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
			Expect(err).To(MatchError(qerr.InvalidStreamID))
		})

		It("does not reject existing streams with even StreamIDs", func() {
			_, err := session.OpenStream(4)
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
			Expect(session.streams).To(HaveLen(2))
			Expect(streamCallbackCalled).To(BeTrue())
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Offset:   2,
				Data:     []byte{0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(2))
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
		})

		It("does not delete streams with Close()", func() {
			str, err := session.OpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
		})

		It("does not delete streams with FIN bit", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
		})

		It("closes streams with FIN bit & close", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
				FinBit:   true,
			})
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).To(MatchError(io.EOF))
			Expect(p).To(Equal([]byte{0xde, 0xca, 0xfb, 0xad}))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
			// We still need to close the stream locally
			session.streams[5].Close()
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).To(BeNil())
		})

		It("closes streams with error", func() {
			testErr := errors.New("test")
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
			Expect(streamCallbackCalled).To(BeTrue())
			p := make([]byte, 4)
			_, err := session.streams[5].Read(p)
			Expect(err).ToNot(HaveOccurred())
			session.closeStreamsWithError(testErr)
			_, err = session.streams[5].Read(p)
			Expect(err).To(MatchError(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).To(BeNil())
		})

		It("removes closed streams from BlockedManager", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			Expect(session.streams[5]).ToNot(BeNil())
			session.blockedManager.AddBlockedStream(5, 4)
			Expect(session.blockedManager.blockedStreams).To(HaveKey(protocol.StreamID(5)))
			err := session.streams[5].Close()
			Expect(err).ToNot(HaveOccurred())
			session.garbageCollectStreams()
			Expect(session.blockedManager.blockedStreams).ToNot(HaveKey(protocol.StreamID(5)))
		})

		It("removes closed streams from WindowUpdateManager", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{0xde, 0xca, 0xfb, 0xad},
			})
			session.updateReceiveFlowControlWindow(5, 0x1337)
			session.streams[5].eof = 1
			session.garbageCollectStreams()
			Expect(session.windowUpdateManager.streamOffsets).ToNot(HaveKey(protocol.StreamID(5)))
		})

		It("closes empty streams with error", func() {
			testErr := errors.New("test")
			session.newStreamImpl(5)
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).ToNot(BeNil())
			session.closeStreamsWithError(testErr)
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(MatchError(testErr))
			session.garbageCollectStreams()
			Expect(session.streams).To(HaveLen(2))
			Expect(session.streams[5]).To(BeNil())
		})

		It("ignores streams that existed previously", func() {
			session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
				FinBit:   true,
			})
			_, err := session.streams[5].Read([]byte{0})
			Expect(err).To(MatchError(io.EOF))
			session.streams[5].Close()
			session.garbageCollectStreams()
			err = session.handleStreamFrame(&frames.StreamFrame{
				StreamID: 5,
				Data:     []byte{},
			})
			Expect(err).To(BeNil())
		})
	})

	Context("handling RST_STREAM frames", func() {
		It("closes the receiving streams for writing and reading", func() {
			s, err := session.OpenStream(5)
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
			_, err := session.OpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 0x8000,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.streams[5].flowController.SendWindowSize()).To(Equal(protocol.ByteCount(0x8000)))
		})

		It("updates the Flow Control Windows of the connection", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   0,
				ByteOffset: 0x800000,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.flowController.SendWindowSize()).To(Equal(protocol.ByteCount(0x800000)))
		})

		It("errors when the stream is not known", func() {
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnInvalidStream))
		})

		It("errors when receiving a WindowUpdateFrame for a closed stream", func() {
			session.streams[5] = nil // this is what the garbageCollectStreams() does when a Stream is closed
			err := session.handleWindowUpdateFrame(&frames.WindowUpdateFrame{
				StreamID:   5,
				ByteOffset: 1337,
			})
			Expect(err).To(MatchError(errWindowUpdateOnClosedStream))
		})
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
			Expect(closeCallbackCalled).To(BeTrue())
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0][len(conn.written[0])-7:]).To(Equal([]byte{0x02, byte(qerr.PeerGoingAway), 0, 0, 0, 0, 0}))
		})

		It("only closes once", func() {
			session.Close(nil)
			session.Close(nil)
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			Expect(conn.written).To(HaveLen(1))
		})

		It("closes streams with proper error", func() {
			testErr := errors.New("test error")
			s, err := session.OpenStream(5)
			Expect(err).NotTo(HaveOccurred())
			session.Close(testErr)
			Expect(closeCallbackCalled).To(BeTrue())
			Eventually(func() int { return runtime.NumGoroutine() }).Should(Equal(nGoRoutinesBefore))
			n, err := s.Read([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError(testErr))
			n, err = s.Write([]byte{0})
			Expect(n).To(BeZero())
			Expect(err).To(MatchError(testErr))
		})
	})

	Context("sending packets", func() {
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
			session.queueStreamFrame(&frames.StreamFrame{
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
			_, err := session.OpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.updateReceiveFlowControlWindow(5, 0xDECAFBAD)
			Expect(err).ToNot(HaveOccurred())
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
		})

		It("repeats a WindowUpdate frame in WindowUpdateNumRepetitions packets", func() {
			_, err := session.OpenStream(5)
			Expect(err).ToNot(HaveOccurred())
			err = session.updateReceiveFlowControlWindow(5, 0xDECAFBAD)
			Expect(err).ToNot(HaveOccurred())
			for i := uint8(0); i < protocol.WindowUpdateNumRepetitions; i++ {
				err = session.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(conn.written[i]).To(ContainSubstring(string([]byte{0x04, 0x05, 0, 0, 0})))
			}
			Expect(conn.written).To(HaveLen(int(protocol.WindowUpdateNumRepetitions)))
			err = session.sendPacket()
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(int(protocol.WindowUpdateNumRepetitions))) // no packet was sent
		})

		It("sends public reset", func() {
			err := session.sendPublicReset(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(conn.written).To(HaveLen(1))
			Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
		})

		Context("Blocked", func() {
			It("queues a Blocked frames", func() {
				len := 500
				frame := frames.StreamFrame{
					StreamID: 0x1337,
					Data:     bytes.Repeat([]byte{'f'}, len),
				}
				session.streamBlocked(0x1337, protocol.ByteCount(len))
				session.packer.AddStreamFrame(frame)
				err := session.sendPacket()
				Expect(err).NotTo(HaveOccurred())
				Expect(conn.written).To(HaveLen(1))
				Expect(conn.written[0]).To(ContainSubstring(string([]byte{0x05, 0x37, 0x13, 0, 0})))
			})

			It("does not send a blocked frame for a stream if a WindowUpdate arrived before", func() {
				len := 500
				_, err := session.OpenStream(0x1337)
				Expect(err).ToNot(HaveOccurred())
				session.streamBlocked(0x1337, protocol.ByteCount(len))
				wuf := frames.WindowUpdateFrame{
					StreamID:   0x1337,
					ByteOffset: protocol.ByteCount(len * 2),
				}
				err = session.handleWindowUpdateFrame(&wuf)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.blockedManager.GetBlockedFrame(0x1337, protocol.ByteCount(len))).To(BeNil())
			})

			It("does not send a blocked frame for the connection if a WindowUpdate arrived before", func() {
				len := 500
				session.streamBlocked(0, protocol.ByteCount(len))
				wuf := frames.WindowUpdateFrame{
					StreamID:   0,
					ByteOffset: protocol.ByteCount(len * 2),
				}
				err := session.handleWindowUpdateFrame(&wuf)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.blockedManager.GetBlockedFrame(0, protocol.ByteCount(len))).To(BeNil())
			})
		})
	})

	Context("retransmissions", func() {
		It("sends a StreamFrame from a packet queued for retransmission", func() {
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
			Expect(conn.written[0]).To(ContainSubstring("foobar1234567"))
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
	})

	Context("scheduling sending", func() {
		It("sends after queuing a stream frame", func() {
			Expect(session.sendingScheduled).NotTo(Receive())
			err := session.queueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			// Try again, so that we detect blocking scheduleSending
			err = session.queueStreamFrame(&frames.StreamFrame{StreamID: 1})
			Expect(err).ToNot(HaveOccurred())
			Expect(session.sendingScheduled).To(Receive())
		})

		Context("bundling of small packets", func() {
			It("bundles two small frames into one packet", func() {
				go session.run()

				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar2"),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(1))
			})

			It("sends out two big frames in two packet", func() {
				go session.run()

				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     bytes.Repeat([]byte{'e'}, int(protocol.SmallPacketPayloadSizeThreshold+50)),
				})
				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     bytes.Repeat([]byte{'f'}, int(protocol.SmallPacketPayloadSizeThreshold+50)),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(2))
			})

			It("sends out two small frames that are written to long after one another into two packet", func() {
				go session.run()

				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				time.Sleep(10 * protocol.SmallPacketSendDelay)
				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar2"),
				})
				time.Sleep(10 * time.Millisecond)
				Expect(conn.written).To(HaveLen(2))
			})

			It("sends a queued ACK frame only once", func() {
				go session.run()

				packetNumber := protocol.PacketNumber(0x1337)
				session.receivedPacketHandler.ReceivedPacket(packetNumber, true)
				session.queueStreamFrame(&frames.StreamFrame{
					StreamID: 5,
					Data:     []byte("foobar1"),
				})
				time.Sleep(10 * protocol.SmallPacketSendDelay)
				session.queueStreamFrame(&frames.StreamFrame{
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
		go session.run()
		s, err := session.OpenStream(3)
		Expect(err).NotTo(HaveOccurred())
		err = session.handleStreamFrame(&frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("4242\x00\x00\x00\x00"),
		})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() bool { return atomic.LoadUint32(&session.closed) != 0 }).Should(BeTrue())
		_, err = s.Write([]byte{})
		Expect(err).To(MatchError(qerr.InvalidCryptoMessageType))
	})

	It("sends public reset after too many undecryptable packets", func() {
		// Write protocol.MaxUndecryptablePackets and expect a public reset to happen
		for i := 0; i < protocol.MaxUndecryptablePackets; i++ {
			hdr := &publicHeader{
				PacketNumber: protocol.PacketNumber(i + 1),
			}
			session.handlePacket(nil, hdr, []byte("foobar"))
		}
		session.run()

		Expect(conn.written).To(HaveLen(1))
		Expect(conn.written[0]).To(ContainSubstring(string([]byte("PRST"))))
	})

	It("unqueues undecryptable packets for later decryption", func() {
		session.undecryptablePackets = []receivedPacket{{
			nil,
			&publicHeader{PacketNumber: protocol.PacketNumber(42)},
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
		session.run() // Would normally not return
		Expect(conn.written[0]).To(ContainSubstring("No recent network activity."))
		close(done)
	}, 3)

	It("errors when the SentPacketHandler has too many packets tracked", func() {
		streamFrame := frames.StreamFrame{StreamID: 5, Data: []byte("foobar")}
		for i := uint32(1); i < protocol.MaxTrackedSentPackets+10; i++ {
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
		for i := 0; i < protocol.MaxSessionUnprocessedPackets+10; i++ {
			session.handlePacket(nil, nil, nil)
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
			err = session.sentPacketHandler.ReceivedAck(&frames.AckFrame{LargestObserved: p})
			Expect(err).NotTo(HaveOccurred())
		}
		// Now, we send a single packet, and expect that it was retransmitted later
		go session.run()
		Expect(conn.written).To(BeEmpty())
		err := session.sentPacketHandler.SentPacket(&ackhandler.Packet{
			PacketNumber: n,
			Length:       1,
			Frames: []frames.Frame{&frames.StreamFrame{
				Data: bytes.Repeat([]byte{'a'}, int(protocol.SmallPacketPayloadSizeThreshold)+1),
			}},
		})
		session.packer.lastPacketNumber = n
		Expect(err).NotTo(HaveOccurred())
		session.scheduleSending()
		Eventually(func() bool { return len(conn.written) > 0 }).Should(BeTrue())
	})

	Context("counting streams", func() {
		It("errors when too many streams are opened", func(done Done) {
			// 1.1 * 100
			for i := 2; i <= 110; i++ {
				_, err := session.OpenStream(protocol.StreamID(i))
				Expect(err).NotTo(HaveOccurred())
			}
			_, err := session.OpenStream(protocol.StreamID(111))
			Expect(err).To(MatchError(qerr.TooManyOpenStreams))
			Eventually(session.closeChan).Should(Receive())
			close(done)
		})

		It("does not error when many streams are opened and closed", func() {
			for i := 2; i <= 1000; i++ {
				s, err := session.OpenStream(protocol.StreamID(i))
				Expect(err).NotTo(HaveOccurred())
				err = s.Close()
				Expect(err).NotTo(HaveOccurred())
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
				LargestObserved: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
			err = session.handleFrames([]frames.Frame{&frames.AckFrame{
				LargestObserved: 1,
			}})
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
