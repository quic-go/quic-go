package quic

import (
	"bytes"
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
		conn = newMockPacketConn()
		handler = newPacketHandlerMap(conn, 5, utils.DefaultLogger).(*packetHandlerMap)
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
		It("handles packets for different packet handlers on the same packet conn", func() {
			connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
			connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
			packetHandler1 := NewMockPacketHandler(mockCtrl)
			packetHandler2 := NewMockPacketHandler(mockCtrl)
			handledPacket1 := make(chan struct{})
			handledPacket2 := make(chan struct{})
			packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.hdr.DestConnectionID).To(Equal(connID1))
				close(handledPacket1)
			})
			packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.hdr.DestConnectionID).To(Equal(connID2))
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
			_, err := handler.parsePacket(nil, nil, []byte{0, 1, 2, 3})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error parsing packet:"))
		})

		It("deletes removed session immediately", func() {
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
			handler.Add(connID, NewMockPacketHandler(mockCtrl))
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

		Context("coalesced packets", func() {
			It("cuts packets to the right length", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				data := append(getPacketWithLength(connID, 456), make([]byte, 1000)...)
				packetHandler := NewMockPacketHandler(mockCtrl)
				packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					Expect(p.data).To(HaveLen(456 + int(p.hdr.ParsedLen())))
				})
				handler.Add(connID, packetHandler)
				handler.handlePacket(nil, nil, data)
			})

			It("handles coalesced packets", func() {
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				packetHandler := NewMockPacketHandler(mockCtrl)
				handledPackets := make(chan *receivedPacket, 3)
				packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
					handledPackets <- p
				}).Times(3)
				handler.Add(connID, packetHandler)

				buffer := getPacketBuffer()
				packet := buffer.Slice[:0]
				packet = append(packet, append(getPacketWithLength(connID, 10), make([]byte, 10-2 /* packet number len */)...)...)
				packet = append(packet, append(getPacketWithLength(connID, 20), make([]byte, 20-2 /* packet number len */)...)...)
				packet = append(packet, append(getPacketWithLength(connID, 30), make([]byte, 30-2 /* packet number len */)...)...)
				conn.dataToRead <- packet

				now := time.Now()
				for i := 1; i <= 3; i++ {
					var p *receivedPacket
					Eventually(handledPackets).Should(Receive(&p))
					Expect(p.hdr.DestConnectionID).To(Equal(connID))
					Expect(p.hdr.Length).To(BeEquivalentTo(10 * i))
					Expect(p.data).To(HaveLen(int(p.hdr.ParsedLen() + p.hdr.Length)))
					Expect(p.rcvTime).To(BeTemporally("~", now, scaleDuration(20*time.Millisecond)))
					Expect(p.buffer.refCount).To(Equal(3))
				}
			})

			It("ignores coalesced packet parts if the connection IDs don't match", func() {
				connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
				connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}

				buffer := getPacketBuffer()
				packet := buffer.Slice[:0]
				// var packet []byte
				packet = append(packet, getPacket(connID1)...)
				packet = append(packet, getPacket(connID2)...)

				packets, err := handler.parsePacket(&net.UDPAddr{}, buffer, packet)
				Expect(err).To(MatchError("coalesced packet has different destination connection ID: 0x0807060504030201, expected 0x0102030405060708"))
				Expect(packets).To(HaveLen(1))
				Expect(packets[0].hdr.DestConnectionID).To(Equal(connID1))
				Expect(packets[0].buffer.refCount).To(Equal(1))
			})
		})
	})

	Context("stateless reset handling", func() {
		It("handles packets for connections added with a reset token", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			// first send a normal packet
			handledPacket := make(chan struct{})
			packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.hdr.DestConnectionID).To(Equal(connID))
				close(handledPacket)
			})
			conn.dataToRead <- getPacket(connID)
			Eventually(handledPacket).Should(BeClosed())
		})

		It("handles stateless resets", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			packet := append([]byte{0x40} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			destroyed := make(chan struct{})
			packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
				close(destroyed)
			})
			conn.dataToRead <- packet
			Eventually(destroyed).Should(BeClosed())
		})

		It("detects a stateless that is coalesced with another packet", func() {
			packetHandler := NewMockPacketHandler(mockCtrl)
			connID := protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, packetHandler, token)
			fakeConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
			packet := getPacket(fakeConnID)
			reset := append([]byte{0x40} /* short header packet */, fakeConnID...)
			reset = append(reset, make([]byte, 50)...) // add some "random" data
			reset = append(reset, token[:]...)
			destroyed := make(chan struct{})
			packetHandler.EXPECT().destroy(errors.New("received a stateless reset")).Do(func(error) {
				close(destroyed)
			})
			conn.dataToRead <- append(packet, reset...)
			Eventually(destroyed).Should(BeClosed())
		})

		It("deletes reset tokens when the session is retired", func() {
			handler.deleteRetiredSessionsAfter = scaleDuration(10 * time.Millisecond)
			connID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0x42}
			token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			handler.AddWithResetToken(connID, NewMockPacketHandler(mockCtrl), token)
			handler.Retire(connID)
			time.Sleep(scaleDuration(30 * time.Millisecond))
			handler.handlePacket(nil, nil, getPacket(connID))
			// don't EXPECT any calls to handlePacket of the MockPacketHandler
			packet := append([]byte{0x40, 0xde, 0xca, 0xfb, 0xad, 0x99} /* short header packet */, make([]byte, 50)...)
			packet = append(packet, token[:]...)
			handler.handlePacket(nil, nil, packet)
			// don't EXPECT any calls to handlePacket of the MockPacketHandler
			Expect(handler.resetTokens).To(BeEmpty())
		})
	})

	Context("running a server", func() {
		It("adds a server", func() {
			connID := protocol.ConnectionID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			p := getPacket(connID)
			server := NewMockUnknownPacketHandler(mockCtrl)
			server.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				Expect(p.hdr.DestConnectionID).To(Equal(connID))
			})
			handler.SetServer(server)
			handler.handlePacket(nil, nil, p)
		})

		It("closes all server sessions", func() {
			clientSess := NewMockPacketHandler(mockCtrl)
			clientSess.EXPECT().GetPerspective().Return(protocol.PerspectiveClient)
			serverSess := NewMockPacketHandler(mockCtrl)
			serverSess.EXPECT().GetPerspective().Return(protocol.PerspectiveServer)
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
})
