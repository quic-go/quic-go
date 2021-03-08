package quic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"time"

	mocklogging "github.com/lucas-clemente/quic-go/internal/mocks/logging"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Handler Map", func() {
	type packetToRead struct {
		addr net.Addr
		data []byte
		err  error
	}

	var (
		handler    *packetHandlerMap
		conn       *MockPacketConn
		tracer     *mocklogging.MockTracer
		packetChan chan packetToRead

		connIDLen         int
		statelessResetKey []byte
	)

	getPacketWithPacketType := func(connID protocol.ConnectionID, t protocol.PacketType, length protocol.ByteCount) []byte {
		buf := &bytes.Buffer{}
		Expect((&wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             t,
				DestConnectionID: connID,
				Length:           length,
				Version:          protocol.VersionTLS,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Write(buf, protocol.VersionWhatever)).To(Succeed())
		return buf.Bytes()
	}

	getPacket := func(connID protocol.ConnectionID) []byte {
		return getPacketWithPacketType(connID, protocol.PacketTypeHandshake, 2)
	}

	BeforeEach(func() {
		statelessResetKey = nil
		connIDLen = 0
		tracer = mocklogging.NewMockTracer(mockCtrl)
		packetChan = make(chan packetToRead, 10)
	})

	JustBeforeEach(func() {
		conn = NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(b []byte) (int, net.Addr, error) {
			p, ok := <-packetChan
			if !ok {
				return 0, nil, errors.New("closed")
			}
			return copy(b, p.data), p.addr, p.err
		}).AnyTimes()
		phm, err := newPacketHandlerMap(conn, connIDLen, statelessResetKey, tracer, utils.DefaultLogger)
		Expect(err).ToNot(HaveOccurred())
		handler = phm.(*packetHandlerMap)
	})

	It("closes", func() {
		getMultiplexer() // make the sync.Once execute
		// replace the clientMuxer. getClientMultiplexer will now return the MockMultiplexer
		mockMultiplexer := NewMockMultiplexer(mockCtrl)
		origMultiplexer := connMuxer
		connMuxer = mockMultiplexer

		defer func() {
			connMuxer = origMultiplexer
		}()

		testErr := errors.New("test error	")
		sess1 := NewMockPacketHandler(mockCtrl)
		sess1.EXPECT().destroy(testErr)
		sess2 := NewMockPacketHandler(mockCtrl)
		sess2.EXPECT().destroy(testErr)
		handler.Add(protocol.ConnectionID{1, 1, 1, 1}, sess1)
		handler.Add(protocol.ConnectionID{2, 2, 2, 2}, sess2)
		mockMultiplexer.EXPECT().RemoveConn(gomock.Any())
		handler.close(testErr)
		close(packetChan)
		Eventually(handler.listening).Should(BeClosed())
	})

	Context("other operations", func() {
		AfterEach(func() {
			// delete sessions and the server before closing
			// They might be mock implementations, and we'd have to register the expected calls before otherwise.
			handler.mutex.Lock()
			for connID := range handler.handlers {
				delete(handler.handlers, connID)
			}
			handler.server = nil
			handler.mutex.Unlock()
			conn.EXPECT().Close().MaxTimes(1)
			close(packetChan)
			handler.Destroy()
			Eventually(handler.listening).Should(BeClosed())
		})

		Context("handling packets", func() {
			BeforeEach(func() {
				connIDLen = 5
			})

			It("handles packets for different packet handlers on the same packet conn", func() {
				connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
				packetHandler1 := NewMockPacketHandler(mockCtrl)
				packetHandler2 := NewMockPacketHandler(mockCtrl)
				handledPacket1 := make(chan struct{})
				handledPacket2 := make(chan struct{})
				packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					connID, err := wire.ParseConnectionID(p.data, 0)
					Expect(err).ToNot(HaveOccurred())
					Expect(connID).To(Equal(connID1))
					close(handledPacket1)
				})
				packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					connID, err := wire.ParseConnectionID(p.data, 0)
					Expect(err).ToNot(HaveOccurred())
					Expect(connID).To(Equal(connID2))
					close(handledPacket2)
				})
				handler.Add(connID1, packetHandler1)
				handler.Add(connID2, packetHandler2)
				packetChan <- packetToRead{data: getPacket(connID1)}
				packetChan <- packetToRead{data: getPacket(connID2)}

				Eventually(handledPacket1).Should(BeClosed())
				Eventually(handledPacket2).Should(BeClosed())
			})

			It("drops unparseable packets", func() {
				addr := &net.UDPAddr{IP: net.IPv4(9, 8, 7, 6), Port: 1234}
				tracer.EXPECT().DroppedPacket(addr, logging.PacketTypeNotDetermined, protocol.ByteCount(4), logging.PacketDropHeaderParseError)
				handler.handlePacket(&receivedPacket{
					buffer:     getPacketBuffer(),
					remoteAddr: addr,
					data:       []byte{0, 1, 2, 3},
				})
			})

			It("deletes removed sessions immediately", func() {
				handler.deleteRetiredSessionsAfter = time.Hour
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				handler.Add(connID, NewMockPacketHandler(mockCtrl))
				handler.Remove(connID)
				handler.handlePacket(&receivedPacket{data: getPacket(connID)})
				// don't EXPECT any calls to handlePacket of the MockPacketHandler
			})

			It("deletes retired session entries after a wait time", func() {
				handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				sess := NewMockPacketHandler(mockCtrl)
				handler.Add(connID, sess)
				handler.Retire(connID)
				time.Sleep(scaleDuration(30 * time.Millisecond))
				handler.handlePacket(&receivedPacket{data: getPacket(connID)})
				// don't EXPECT any calls to handlePacket of the MockPacketHandler
			})

			It("passes packets arriving late for closed sessions to that session", func() {
				handler.deleteRetiredSessionsAfter = time.Hour
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				packetHandler := NewMockPacketHandler(mockCtrl)
				handled := make(chan struct{})
				packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					close(handled)
				})
				handler.Add(connID, packetHandler)
				handler.Retire(connID)
				handler.handlePacket(&receivedPacket{data: getPacket(connID)})
				Eventually(handled).Should(BeClosed())
			})

			It("drops packets for unknown receivers", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				handler.handlePacket(&receivedPacket{data: getPacket(connID)})
			})

			It("closes the packet handlers when reading from the conn fails", func() {
				done := make(chan struct{})
				packetHandler := NewMockPacketHandler(mockCtrl)
				packetHandler.EXPECT().destroy(gomock.Any()).Do(func(e error) {
					Expect(e).To(HaveOccurred())
					close(done)
				})
				handler.Add(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
				packetChan <- packetToRead{err: errors.New("read failed")}
				Eventually(done).Should(BeClosed())
			})

			It("continues listening for temporary errors", func() {
				packetHandler := NewMockPacketHandler(mockCtrl)
				handler.Add(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
				err := deadlineError{}
				Expect(err.Temporary()).To(BeTrue())
				packetChan <- packetToRead{err: err}
				// don't EXPECT any calls to packetHandler.destroy
				time.Sleep(50 * time.Millisecond)
			})

			It("says if a connection ID is already taken", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				Expect(handler.Add(connID, NewMockPacketHandler(mockCtrl))).To(BeTrue())
				Expect(handler.Add(connID, NewMockPacketHandler(mockCtrl))).To(BeFalse())
			})

			It("says if a connection ID is already taken, for AddWithConnID", func() {
				clientDestConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				newConnID1 := protocol.ConnectionID{1, 2, 3, 4}
				newConnID2 := protocol.ConnectionID{4, 3, 2, 1}
				Expect(handler.AddWithConnID(clientDestConnID, newConnID1, func() packetHandler { return NewMockPacketHandler(mockCtrl) })).To(BeTrue())
				Expect(handler.AddWithConnID(clientDestConnID, newConnID2, func() packetHandler { return NewMockPacketHandler(mockCtrl) })).To(BeFalse())
			})
		})

		Context("running a server", func() {
			It("adds a server", func() {
				connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
				p := getPacket(connID)
				server := NewMockUnknownPacketHandler(mockCtrl)
				server.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					cid, err := wire.ParseConnectionID(p.data, 0)
					Expect(err).ToNot(HaveOccurred())
					Expect(cid).To(Equal(connID))
				})
				handler.SetServer(server)
				handler.handlePacket(&receivedPacket{data: p})
			})

			It("closes all server sessions", func() {
				handler.SetServer(NewMockUnknownPacketHandler(mockCtrl))
				clientSess := NewMockPacketHandler(mockCtrl)
				clientSess.EXPECT().getPerspective().Return(protocol.PerspectiveClient)
				serverSess := NewMockPacketHandler(mockCtrl)
				serverSess.EXPECT().getPerspective().Return(protocol.PerspectiveServer)
				serverSess.EXPECT().shutdown()

				handler.Add(protocol.ConnectionID{1, 1, 1, 1}, clientSess)
				handler.Add(protocol.ConnectionID{2, 2, 2, 2}, serverSess)
				handler.CloseServer()
			})

			It("stops handling packets with unknown connection IDs after the server is closed", func() {
				connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
				p := getPacket(connID)
				server := NewMockUnknownPacketHandler(mockCtrl)
				// don't EXPECT any calls to server.handlePacket
				handler.SetServer(server)
				handler.CloseServer()
				handler.handlePacket(&receivedPacket{data: p})
			})
		})

		Context("0-RTT", func() {
			JustBeforeEach(func() {
				handler.zeroRTTQueueDuration = time.Hour
				server := NewMockUnknownPacketHandler(mockCtrl)
				// we don't expect any calls to server.handlePacket
				handler.SetServer(server)
			})

			It("queues 0-RTT packets", func() {
				server := NewMockUnknownPacketHandler(mockCtrl)
				// don't EXPECT any calls to server.handlePacket
				handler.SetServer(server)
				connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
				p1 := &receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 1)}
				p2 := &receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 2)}
				p3 := &receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 3)}
				handler.handlePacket(p1)
				handler.handlePacket(p2)
				handler.handlePacket(p3)
				sess := NewMockPacketHandler(mockCtrl)
				done := make(chan struct{})
				gomock.InOrder(
					sess.EXPECT().handlePacket(p1),
					sess.EXPECT().handlePacket(p2),
					sess.EXPECT().handlePacket(p3).Do(func(packet *receivedPacket) { close(done) }),
				)
				handler.AddWithConnID(connID, protocol.ConnectionID{1, 2, 3, 4}, func() packetHandler { return sess })
				Eventually(done).Should(BeClosed())
			})

			It("directs 0-RTT packets to existing sessions", func() {
				connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
				sess := NewMockPacketHandler(mockCtrl)
				handler.AddWithConnID(connID, protocol.ConnectionID{1, 2, 3, 4}, func() packetHandler { return sess })
				p1 := &receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 1)}
				sess.EXPECT().handlePacket(p1)
				handler.handlePacket(p1)
			})

			It("limits the number of 0-RTT queues", func() {
				for i := 0; i < protocol.Max0RTTQueues; i++ {
					connID := make(protocol.ConnectionID, 8)
					rand.Read(connID)
					p := &receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 1)}
					handler.handlePacket(p)
				}
				// We're already storing the maximum number of queues. This packet will be dropped.
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9}
				handler.handlePacket(&receivedPacket{data: getPacketWithPacketType(connID, protocol.PacketType0RTT, 1)})
				// Don't EXPECT any handlePacket() calls.
				sess := NewMockPacketHandler(mockCtrl)
				handler.AddWithConnID(connID, protocol.ConnectionID{1, 2, 3, 4}, func() packetHandler { return sess })
				time.Sleep(20 * time.Millisecond)
			})

			It("deletes queues if no session is created for this connection ID", func() {
				queueDuration := scaleDuration(10 * time.Millisecond)
				handler.zeroRTTQueueDuration = queueDuration

				server := NewMockUnknownPacketHandler(mockCtrl)
				// don't EXPECT any calls to server.handlePacket
				handler.SetServer(server)
				connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
				p1 := &receivedPacket{
					data:   getPacketWithPacketType(connID, protocol.PacketType0RTT, 1),
					buffer: getPacketBuffer(),
				}
				p2 := &receivedPacket{
					data:   getPacketWithPacketType(connID, protocol.PacketType0RTT, 2),
					buffer: getPacketBuffer(),
				}
				handler.handlePacket(p1)
				handler.handlePacket(p2)
				// wait a bit. The queue should now already be deleted.
				time.Sleep(queueDuration * 3)
				// Don't EXPECT any handlePacket() calls.
				sess := NewMockPacketHandler(mockCtrl)
				handler.AddWithConnID(connID, protocol.ConnectionID{1, 2, 3, 4}, func() packetHandler { return sess })
				time.Sleep(20 * time.Millisecond)
			})
		})

		Context("stateless resets", func() {
			BeforeEach(func() {
				connIDLen = 5
			})

			Context("handling", func() {
				It("handles stateless resets", func() {
					packetHandler := NewMockPacketHandler(mockCtrl)
					token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
					handler.AddResetToken(token, packetHandler)
					destroyed := make(chan struct{})
					packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
					packet = append(packet, token[:]...)
					packetHandler.EXPECT().destroy(gomock.Any()).Do(func(err error) {
						defer GinkgoRecover()
						defer close(destroyed)
						Expect(err).To(HaveOccurred())
						var resetErr statelessResetErr
						Expect(errors.As(err, &resetErr)).To(BeTrue())
						Expect(err.Error()).To(ContainSubstring("received a stateless reset"))
						Expect(resetErr.token).To(Equal(token))
					})
					packetChan <- packetToRead{data: packet}
					Eventually(destroyed).Should(BeClosed())
				})

				It("handles stateless resets for 0-length connection IDs", func() {
					handler.connIDLen = 0
					packetHandler := NewMockPacketHandler(mockCtrl)
					token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
					handler.AddResetToken(token, packetHandler)
					destroyed := make(chan struct{})
					packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
					packet = append(packet, token[:]...)
					packetHandler.EXPECT().destroy(gomock.Any()).Do(func(err error) {
						defer GinkgoRecover()
						Expect(err).To(HaveOccurred())
						var resetErr statelessResetErr
						Expect(errors.As(err, &resetErr)).To(BeTrue())
						Expect(err.Error()).To(ContainSubstring("received a stateless reset"))
						Expect(resetErr.token).To(Equal(token))
						close(destroyed)
					})
					packetChan <- packetToRead{data: packet}
					Eventually(destroyed).Should(BeClosed())
				})

				It("removes reset tokens", func() {
					connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0x42}
					packetHandler := NewMockPacketHandler(mockCtrl)
					handler.Add(connID, packetHandler)
					token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
					handler.AddResetToken(token, NewMockPacketHandler(mockCtrl))
					handler.RemoveResetToken(token)
					// don't EXPECT any call to packetHandler.destroy()
					packetHandler.EXPECT().handlePacket(gomock.Any())
					p := append([]byte{0x40} /* short header packet */, connID.Bytes()...)
					p = append(p, make([]byte, 50)...)
					p = append(p, token[:]...)

					handler.handlePacket(&receivedPacket{data: p})
				})

				It("ignores packets too small to contain a stateless reset", func() {
					handler.connIDLen = 0
					packetHandler := NewMockPacketHandler(mockCtrl)
					token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
					handler.AddResetToken(token, packetHandler)
					done := make(chan struct{})
					// don't EXPECT any calls here, but register the closing of the done channel
					packetHandler.EXPECT().destroy(gomock.Any()).Do(func(error) {
						close(done)
					}).AnyTimes()
					packetChan <- packetToRead{data: append([]byte{0x40} /* short header packet */, token[:15]...)}
					Consistently(done).ShouldNot(BeClosed())
				})
			})

			Context("generating", func() {
				BeforeEach(func() {
					key := make([]byte, 32)
					rand.Read(key)
					statelessResetKey = key
				})

				It("generates stateless reset tokens", func() {
					connID1 := []byte{0xde, 0xad, 0xbe, 0xef}
					connID2 := []byte{0xde, 0xca, 0xfb, 0xad}
					Expect(handler.GetStatelessResetToken(connID1)).ToNot(Equal(handler.GetStatelessResetToken(connID2)))
				})

				It("sends stateless resets", func() {
					addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
					p := append([]byte{40}, make([]byte, 100)...)
					done := make(chan struct{})
					conn.EXPECT().WriteTo(gomock.Any(), addr).Do(func(b []byte, _ net.Addr) {
						defer close(done)
						Expect(b[0] & 0x80).To(BeZero()) // short header packet
						Expect(b).To(HaveLen(protocol.MinStatelessResetSize))
					})
					handler.handlePacket(&receivedPacket{
						buffer:     getPacketBuffer(),
						remoteAddr: addr,
						data:       p,
					})
					Eventually(done).Should(BeClosed())
				})

				It("doesn't send stateless resets for small packets", func() {
					addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
					p := append([]byte{40}, make([]byte, protocol.MinStatelessResetSize-2)...)
					handler.handlePacket(&receivedPacket{
						buffer:     getPacketBuffer(),
						remoteAddr: addr,
						data:       p,
					})
					// make sure there are no Write calls on the packet conn
					time.Sleep(50 * time.Millisecond)
				})
			})

			Context("if no key is configured", func() {
				It("doesn't send stateless resets", func() {
					addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
					p := append([]byte{40}, make([]byte, 100)...)
					handler.handlePacket(&receivedPacket{
						buffer:     getPacketBuffer(),
						remoteAddr: addr,
						data:       p,
					})
					// make sure there are no Write calls on the packet conn
					time.Sleep(50 * time.Millisecond)
				})
			})
		})
	})
})
