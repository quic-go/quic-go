package quic

import (
	"crypto/rand"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Handler Map", func() {
	It("adds and gets", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		handler := NewMockPacketHandler(mockCtrl)
		Expect(m.Add(connID, handler)).To(BeTrue())
		h, ok := m.Get(connID)
		Expect(ok).To(BeTrue())
		Expect(h).To(Equal(handler))
	})

	It("refused to add duplicates", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		handler := NewMockPacketHandler(mockCtrl)
		Expect(m.Add(connID, handler)).To(BeTrue())
		Expect(m.Add(connID, handler)).To(BeFalse())
	})

	It("removes", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		handler := NewMockPacketHandler(mockCtrl)
		Expect(m.Add(connID, handler)).To(BeTrue())
		m.Remove(connID)
		_, ok := m.Get(connID)
		Expect(ok).To(BeFalse())
		Expect(m.Add(connID, handler)).To(BeTrue())
	})

	It("retires", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		dur := scaleDuration(50 * time.Millisecond)
		m.deleteRetiredConnsAfter = dur
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		handler := NewMockPacketHandler(mockCtrl)
		Expect(m.Add(connID, handler)).To(BeTrue())
		m.Retire(connID)
		_, ok := m.Get(connID)
		Expect(ok).To(BeTrue())
		time.Sleep(dur)
		Eventually(func() bool { _, ok := m.Get(connID); return ok }).Should(BeFalse())
	})

	It("adds newly to-be-constructed handlers", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		var called bool
		connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		connID2 := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
		Expect(m.AddWithConnID(connID1, connID2, func() (packetHandler, bool) {
			called = true
			return NewMockPacketHandler(mockCtrl), true
		})).To(BeTrue())
		Expect(called).To(BeTrue())
		Expect(m.AddWithConnID(connID1, protocol.ParseConnectionID([]byte{1, 2, 3}), func() (packetHandler, bool) {
			Fail("didn't expect the constructor to be executed")
			return nil, false
		})).To(BeFalse())
	})

	It("adds, gets and removes reset tokens", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}
		handler := NewMockPacketHandler(mockCtrl)
		m.AddResetToken(token, handler)
		h, ok := m.GetByResetToken(token)
		Expect(ok).To(BeTrue())
		Expect(h).To(Equal(h))
		m.RemoveResetToken(token)
		_, ok = m.GetByResetToken(token)
		Expect(ok).To(BeFalse())
	})

	It("generates stateless reset token, if no key is set", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		b := make([]byte, 8)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		token := m.GetStatelessResetToken(connID)
		for i := 0; i < 1000; i++ {
			to := m.GetStatelessResetToken(connID)
			Expect(to).ToNot(Equal(token))
			token = to
		}
	})

	It("generates stateless reset token, if a key is set", func() {
		var key StatelessResetKey
		rand.Read(key[:])
		m := newPacketHandlerMap(&key, nil, utils.DefaultLogger)
		b := make([]byte, 8)
		rand.Read(b)
		connID := protocol.ParseConnectionID(b)
		token := m.GetStatelessResetToken(connID)
		Expect(token).ToNot(BeZero())
		Expect(m.GetStatelessResetToken(connID)).To(Equal(token))
		// generate a new connection ID
		rand.Read(b)
		connID2 := protocol.ParseConnectionID(b)
		Expect(m.GetStatelessResetToken(connID2)).ToNot(Equal(token))
	})

	It("replaces locally closed connections", func() {
		var closePackets []closePacket
		m := newPacketHandlerMap(nil, func(p closePacket) { closePackets = append(closePackets, p) }, utils.DefaultLogger)
		dur := scaleDuration(50 * time.Millisecond)
		m.deleteRetiredConnsAfter = dur

		handler := NewMockPacketHandler(mockCtrl)
		connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
		Expect(m.Add(connID, handler)).To(BeTrue())
		m.ReplaceWithClosed([]protocol.ConnectionID{connID}, protocol.PerspectiveClient, []byte("foobar"))
		h, ok := m.Get(connID)
		Expect(ok).To(BeTrue())
		Expect(h).ToNot(Equal(handler))
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
		h.handlePacket(receivedPacket{remoteAddr: addr})
		Expect(closePackets).To(HaveLen(1))
		Expect(closePackets[0].addr).To(Equal(addr))
		Expect(closePackets[0].payload).To(Equal([]byte("foobar")))

		time.Sleep(dur)
		Eventually(func() bool { _, ok := m.Get(connID); return ok }).Should(BeFalse())
	})

	It("replaces remote closed connections", func() {
		var closePackets []closePacket
		m := newPacketHandlerMap(nil, func(p closePacket) { closePackets = append(closePackets, p) }, utils.DefaultLogger)
		dur := scaleDuration(50 * time.Millisecond)
		m.deleteRetiredConnsAfter = dur

		handler := NewMockPacketHandler(mockCtrl)
		connID := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
		Expect(m.Add(connID, handler)).To(BeTrue())
		m.ReplaceWithClosed([]protocol.ConnectionID{connID}, protocol.PerspectiveClient, nil)
		h, ok := m.Get(connID)
		Expect(ok).To(BeTrue())
		Expect(h).ToNot(Equal(handler))
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
		h.handlePacket(receivedPacket{remoteAddr: addr})
		Expect(closePackets).To(BeEmpty())

		time.Sleep(dur)
		Eventually(func() bool { _, ok := m.Get(connID); return ok }).Should(BeFalse())
	})

	It("closes the server", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		for i := 0; i < 10; i++ {
			conn := NewMockPacketHandler(mockCtrl)
			if i%2 == 0 {
				conn.EXPECT().getPerspective().Return(protocol.PerspectiveClient)
			} else {
				conn.EXPECT().getPerspective().Return(protocol.PerspectiveServer)
				conn.EXPECT().shutdown()
			}
			b := make([]byte, 12)
			rand.Read(b)
			m.Add(protocol.ParseConnectionID(b), conn)
		}
		m.CloseServer()
	})

	It("closes", func() {
		m := newPacketHandlerMap(nil, nil, utils.DefaultLogger)
		testErr := errors.New("shutdown")
		for i := 0; i < 10; i++ {
			conn := NewMockPacketHandler(mockCtrl)
			conn.EXPECT().destroy(testErr)
			b := make([]byte, 12)
			rand.Read(b)
			m.Add(protocol.ParseConnectionID(b), conn)
		}
		m.Close(testErr)
		// check that Close can be called multiple times
		m.Close(errors.New("close"))
	})
})
