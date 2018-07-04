package quic

import (
	"bytes"
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client Multiplexer", func() {
	getPacket := func(connID protocol.ConnectionID) []byte {
		buf := &bytes.Buffer{}
		err := (&wire.Header{
			DestConnectionID: connID,
			PacketNumberLen:  protocol.PacketNumberLen1,
		}).Write(buf, protocol.PerspectiveServer, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		return buf.Bytes()
	}

	It("adds a new packet conn and handles packets", func() {
		conn := newMockPacketConn()
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		packetHandler := NewMockQuicSession(mockCtrl)
		handledPacket := make(chan struct{})
		packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.header.DestConnectionID).To(Equal(connID))
			close(handledPacket)
		})
		packetHandler.EXPECT().GetVersion()
		getMultiplexer().AddConn(conn, 8)
		err := getMultiplexer().AddHandler(conn, connID, packetHandler)
		Expect(err).ToNot(HaveOccurred())
		conn.dataToRead <- getPacket(connID)
		Eventually(handledPacket).Should(BeClosed())
		// makes the listen go routine return
		packetHandler.EXPECT().Close().AnyTimes()
		close(conn.dataToRead)
	})

	It("errors when adding an existing conn with a different connection ID length", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 5)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 6)
		Expect(err).To(MatchError("cannot use 6 byte connection IDs on a connection that is already using 5 byte connction IDs"))
	})

	It("errors when adding a handler for an unknown conn", func() {
		conn := newMockPacketConn()
		err := getMultiplexer().AddHandler(conn, protocol.ConnectionID{1, 2, 3, 4}, NewMockQuicSession(mockCtrl))
		Expect(err).ToNot(MatchError("unknown packet conn"))
	})

	It("handles packets for different packet handlers on the same packet conn", func() {
		conn := newMockPacketConn()
		connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		packetHandler1 := NewMockQuicSession(mockCtrl)
		packetHandler2 := NewMockQuicSession(mockCtrl)
		handledPacket1 := make(chan struct{})
		handledPacket2 := make(chan struct{})
		packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.header.DestConnectionID).To(Equal(connID1))
			close(handledPacket1)
		})
		packetHandler1.EXPECT().GetVersion()
		packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.header.DestConnectionID).To(Equal(connID2))
			close(handledPacket2)
		})
		packetHandler2.EXPECT().GetVersion()
		getMultiplexer().AddConn(conn, connID1.Len())
		Expect(getMultiplexer().AddHandler(conn, connID1, packetHandler1)).To(Succeed())
		Expect(getMultiplexer().AddHandler(conn, connID2, packetHandler2)).To(Succeed())

		conn.dataToRead <- getPacket(connID1)
		conn.dataToRead <- getPacket(connID2)
		Eventually(handledPacket1).Should(BeClosed())
		Eventually(handledPacket2).Should(BeClosed())

		// makes the listen go routine return
		packetHandler1.EXPECT().Close().AnyTimes()
		packetHandler2.EXPECT().Close().AnyTimes()
		close(conn.dataToRead)
	})

	It("drops unparseable packets", func() {
		err := getMultiplexer().(*connMultiplexer).handlePacket(nil, []byte("invalid"), &connManager{connIDLen: 8})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("error parsing invariant header:"))
	})

	It("ignores packets arriving late for closed sessions", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		manager := NewMockPacketHandlerManager(mockCtrl)
		manager.EXPECT().Get(connID).Return(nil, true)
		err := getMultiplexer().(*connMultiplexer).handlePacket(nil, getPacket(connID), &connManager{manager: manager, connIDLen: 8})
		Expect(err).ToNot(HaveOccurred())
	})

	It("drops packets for unknown receivers", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		manager := NewMockPacketHandlerManager(mockCtrl)
		manager.EXPECT().Get(connID).Return(nil, false)
		err := getMultiplexer().(*connMultiplexer).handlePacket(nil, getPacket(connID), &connManager{manager: manager, connIDLen: 8})
		Expect(err).To(MatchError("received a packet with an unexpected connection ID 0x0102030405060708"))
	})

	It("errors on packets that are smaller than the Payload Length in the packet header", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := &wire.Header{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeHandshake,
			PayloadLen:       1000,
			DestConnectionID: connID,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Version:          versionIETFFrames,
		}
		buf := &bytes.Buffer{}
		Expect(hdr.Write(buf, protocol.PerspectiveServer, versionIETFFrames)).To(Succeed())
		buf.Write(bytes.Repeat([]byte{0}, 500))

		sess := NewMockQuicSession(mockCtrl)
		sess.EXPECT().GetVersion().Return(versionIETFFrames)
		manager := NewMockPacketHandlerManager(mockCtrl)
		manager.EXPECT().Get(connID).Return(sess, true)
		err := getMultiplexer().(*connMultiplexer).handlePacket(nil, buf.Bytes(), &connManager{manager: manager, connIDLen: 8})
		Expect(err).To(MatchError("packet payload (500 bytes) is smaller than the expected payload length (1000 bytes)"))
	})

	It("errors on packets that are smaller than the Payload Length in the packet header", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		hdr := &wire.Header{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeHandshake,
			PayloadLen:       456,
			DestConnectionID: connID,
			PacketNumberLen:  protocol.PacketNumberLen1,
			Version:          versionIETFFrames,
		}
		buf := &bytes.Buffer{}
		Expect(hdr.Write(buf, protocol.PerspectiveServer, versionIETFFrames)).To(Succeed())
		buf.Write(bytes.Repeat([]byte{0}, 500))

		sess := NewMockQuicSession(mockCtrl)
		sess.EXPECT().GetVersion().Return(versionIETFFrames)
		sess.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.data).To(HaveLen(456))
		})
		manager := NewMockPacketHandlerManager(mockCtrl)
		manager.EXPECT().Get(connID).Return(sess, true)
		err := getMultiplexer().(*connMultiplexer).handlePacket(nil, buf.Bytes(), &connManager{manager: manager, connIDLen: 8})
		Expect(err).ToNot(HaveOccurred())
	})

	It("closes the packet handlers when reading from the conn fails", func() {
		conn := newMockPacketConn()
		conn.readErr = errors.New("test error")
		done := make(chan struct{})
		packetHandler := NewMockQuicSession(mockCtrl)
		packetHandler.EXPECT().Close().Do(func() {
			close(done)
		})
		getMultiplexer().AddConn(conn, 8)
		Expect(getMultiplexer().AddHandler(conn, protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)).To(Succeed())
		Eventually(done).Should(BeClosed())
	})
})
