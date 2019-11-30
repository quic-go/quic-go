package quic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Handler Map", func() {
	var (
		handler *packetHandlerMap
		conn    *mockPacketConn

		connIDLen         int
		statelessResetKey []byte
	)

	getPacketWithLength := func(connID protocol.ConnectionID, length protocol.ByteCount) []byte {
		buf := &bytes.Buffer{}
		Expect((&wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeHandshake,
				DestConnectionID: connID,
				Length:           length,
				Version:          protocol.VersionTLS,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Write(buf, protocol.VersionWhatever)).To(Succeed())
		return buf.Bytes()
	}

	getPacket := func(connID protocol.ConnectionID) []byte {
		return getPacketWithLength(connID, 2)
	}

	BeforeEach(func() {
		statelessResetKey = nil
		connIDLen = 0
	})

	JustBeforeEach(func() {
		conn = newMockPacketConn()
		handler = newPacketHandlerMap(conn, connIDLen, statelessResetKey, utils.DefaultLogger).(*packetHandlerMap)
	})

	AfterEach(func() {
		// delete sessions and the server before closing
		// They might be mock implementations, and we'd have to register the expected calls before otherwise.
		handler.mutex.Lock()
		for connID := range handler.handlers {
			delete(handler.handlers, connID)
		}
		handler.server = nil
		handler.mutex.Unlock()
		handler.Close()
		Eventually(handler.listening).Should(BeClosed())
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

			conn.dataToRead <- getPacket(connID1)
			conn.dataToRead <- getPacket(connID2)
			Eventually(handledPacket1).Should(BeClosed())
			Eventually(handledPacket2).Should(BeClosed())
		})

		It("drops unparseable packets", func() {
			handler.handlePacket(nil, nil, []byte{0, 1, 2, 3})
		})

		It("deletes removed sessions immediately", func() {
			handler.deleteRetiredSessionsAfter = time.Hour
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
			handler.Remove(connID)
			handler.handlePacket(nil, nil, getPacket(connID))
			// don't EXPECT any calls to handlePacket of the MockPacketHandler
		})

		It("deletes retired session entries after a wait time", func() {
			handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			sess := NewMockPacketHandler(mockCtrl)
			handler.Add(connID, sess)
			handler.Retire(connID)
			time.Sleep(scaleDuration(30 * time.Millisecond))
			handler.handlePacket(nil, nil, getPacket(connID))
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
			handler.handlePacket(nil, nil, getPacket(connID))
			Eventually(handled).Should(BeClosed())
		})

		It("drops packets for unknown receivers", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			handler.handlePacket(nil, nil, getPacket(connID))
		})

		It("closes the packet handlers when reading from the conn fails", func() {
			done := make(chan struct{})
			packetHandler := NewMockPacketHandler(mockCtrl)
			packetHandler.EXPECT().destroy(gomock.Any()).Do(func(e error) {
				Expect(e).To(HaveOccurred())
				close(done)
			})
			handler.Add(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
			conn.Close()
			Eventually(done).Should(BeClosed())
		})

		It("says if a connection ID is already taken", func() {
			connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			Expect(handler.AddIfNotTaken(connID, NewMockPacketHandler(mockCtrl))).To(BeTrue())
			Expect(handler.AddIfNotTaken(connID, NewMockPacketHandler(mockCtrl))).To(BeFalse())
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
			handler.handlePacket(nil, nil, p)
		})

		It("closes all server sessions", func() {
			clientSess := NewMockPacketHandler(mockCtrl)
			clientSess.EXPECT().getPerspective().Return(protocol.PerspectiveClient)
			serverSess := NewMockPacketHandler(mockCtrl)
			serverSess.EXPECT().getPerspective().Return(protocol.PerspectiveServer)
			serverSess.EXPECT().Close()

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
			handler.handlePacket(nil, nil, p)
		})
	})

	Context("stateless resets", func() {
		BeforeEach(func() {
			connIDLen = 5
		})

		Context("handling", func() {
			It("handles stateless resets", func() {
				packetHandler := NewMockPacketHandler(mockCtrl)
				token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				handler.AddResetToken(token, packetHandler)
				packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
				packet = append(packet, token[:]...)
				destroyed := make(chan struct{})
				packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
					close(destroyed)
				})
				conn.dataToRead <- packet
				Eventually(destroyed).Should(BeClosed())
			})

			It("handles stateless resets for 0-length connection IDs", func() {
				handler.connIDLen = 0
				packetHandler := NewMockPacketHandler(mockCtrl)
				token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				handler.AddResetToken(token, packetHandler)
				packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
				packet = append(packet, token[:]...)
				destroyed := make(chan struct{})
				packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
					close(destroyed)
				})
				conn.dataToRead <- packet
				Eventually(destroyed).Should(BeClosed())
			})

			It("retires reset tokens", func() {
				handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
				connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0x42}
				packetHandler := NewMockPacketHandler(mockCtrl)
				handler.Add(connID, packetHandler)
				token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				handler.AddResetToken(token, NewMockPacketHandler(mockCtrl))
				handler.RetireResetToken(token)
				packetHandler.EXPECT().handlePacket(gomock.Any())
				p := append([]byte{0x40} /* short header packet */, connID.Bytes()...)
				p = append(p, make([]byte, 50)...)
				p = append(p, token[:]...)

				time.Sleep(scaleDuration(30 * time.Millisecond))
				handler.handlePacket(nil, nil, p)
			})

			It("ignores packets too small to contain a stateless reset", func() {
				handler.connIDLen = 0
				packetHandler := NewMockPacketHandler(mockCtrl)
				token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				handler.AddResetToken(token, packetHandler)
				packet := append([]byte{0x40} /* short header packet */, token[:15]...)
				done := make(chan struct{})
				// don't EXPECT any calls here, but register the closing of the done channel
				packetHandler.EXPECT().destroy(gomock.Any()).Do(func(error) {
					close(done)
				}).AnyTimes()
				conn.dataToRead <- packet
				Consistently(done).ShouldNot(BeClosed())
			})
		})

		Context("generating", func() {
			BeforeEach(func() {
				key := make([]byte, 32)
				rand.Read(key)
				statelessResetKey = key
			})

			It("generates stateless reset tokens when adding new sessions", func() {
				connID1 := []byte{0xde, 0xad, 0xbe, 0xef}
				connID2 := []byte{0xde, 0xca, 0xfb, 0xad}
				token1 := handler.Add(connID1, nil)
				Expect(handler.Add(connID1, nil)).To(Equal(token1))
				Expect(handler.Add(connID2, nil)).ToNot(Equal(token1))
			})

			It("generates stateless reset tokens", func() {
				connID1 := []byte{0xde, 0xad, 0xbe, 0xef}
				connID2 := []byte{0xde, 0xca, 0xfb, 0xad}
				Expect(handler.GetStatelessResetToken(connID1)).ToNot(Equal(handler.GetStatelessResetToken(connID2)))
			})

			It("sends stateless resets", func() {
				addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
				p := append([]byte{40}, make([]byte, 100)...)
				handler.handlePacket(addr, getPacketBuffer(), p)
				var reset mockPacketConnWrite
				Eventually(conn.dataWritten).Should(Receive(&reset))
				Expect(reset.to).To(Equal(addr))
				Expect(reset.data[0] & 0x80).To(BeZero()) // short header packet
				Expect(reset.data).To(HaveLen(protocol.MinStatelessResetSize))
			})

			It("doesn't send stateless resets for small packets", func() {
				addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
				p := append([]byte{40}, make([]byte, protocol.MinStatelessResetSize-2)...)
				handler.handlePacket(addr, getPacketBuffer(), p)
				Consistently(conn.dataWritten).ShouldNot(Receive())
			})
		})

		Context("if no key is configured", func() {
			It("doesn't send stateless resets", func() {
				addr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
				p := append([]byte{40}, make([]byte, 100)...)
				handler.handlePacket(addr, getPacketBuffer(), p)
				Consistently(conn.dataWritten).ShouldNot(Receive())
			})
		})
	})
})
