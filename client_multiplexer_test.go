package quic

import (
	"bytes"
	"errors"
	"time"

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
		conn.dataToRead <- getPacket(connID)
		packetHandler := NewMockQuicSession(mockCtrl)
		handledPacket := make(chan struct{})
		packetHandler.EXPECT().handlePacket(gomock.Any()).Do(func(_ *receivedPacket) {
			close(handledPacket)
		})
		getClientMultiplexer().Add(conn, connID, packetHandler)
		Eventually(handledPacket).Should(BeClosed())
		// makes the listen go routine return
		packetHandler.EXPECT().Close(gomock.Any()).AnyTimes()
		close(conn.dataToRead)
	})

	It("handles packets for different packet handlers on the same packet conn", func() {
		conn := newMockPacketConn()
		connID1 := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		connID2 := protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}
		conn.dataToRead <- getPacket(connID1)
		conn.dataToRead <- getPacket(connID2)
		packetHandler1 := NewMockQuicSession(mockCtrl)
		packetHandler2 := NewMockQuicSession(mockCtrl)
		handledPacket1 := make(chan struct{})
		handledPacket2 := make(chan struct{})
		packetHandler1.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.header.DestConnectionID).To(Equal(connID1))
			close(handledPacket1)
		})
		packetHandler2.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
			Expect(p.header.DestConnectionID).To(Equal(connID2))
			close(handledPacket2)
		})
		getClientMultiplexer().Add(conn, connID1, packetHandler1)
		getClientMultiplexer().Add(conn, connID2, packetHandler2)
		Eventually(handledPacket1).Should(BeClosed())
		Eventually(handledPacket2).Should(BeClosed())
		// makes the listen go routine return
		packetHandler1.EXPECT().Close(gomock.Any()).AnyTimes()
		packetHandler2.EXPECT().Close(gomock.Any()).AnyTimes()
		close(conn.dataToRead)
	})

	It("drops unparseable packets", func() {
		conn := newMockPacketConn()
		connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}
		conn.dataToRead <- []byte("invalid header")
		packetHandler := NewMockQuicSession(mockCtrl)
		getClientMultiplexer().Add(conn, connID, packetHandler)
		time.Sleep(100 * time.Millisecond) // give the listen go routine some time to process the packet
		packetHandler.EXPECT().Close(gomock.Any()).AnyTimes()
		close(conn.dataToRead)
	})

	It("drops packets for unknown receivers", func() {
		conn := newMockPacketConn()
		conn.dataToRead <- getPacket(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8})
		packetHandler := NewMockQuicSession(mockCtrl)
		getClientMultiplexer().Add(conn, protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1}, packetHandler)
		time.Sleep(100 * time.Millisecond) // give the listen go routine some time to process the packet
		// makes the listen go routine return
		packetHandler.EXPECT().Close(gomock.Any()).AnyTimes()
		close(conn.dataToRead)
	})

	It("closes the packet handlers when reading from the conn fails", func() {
		conn := newMockPacketConn()
		testErr := errors.New("test error")
		conn.readErr = testErr
		done := make(chan struct{})
		packetHandler := NewMockQuicSession(mockCtrl)
		packetHandler.EXPECT().Close(testErr).Do(func(error) {
			close(done)
		})
		getClientMultiplexer().Add(conn, protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}, packetHandler)
		Eventually(done).Should(BeClosed())
	})
})
