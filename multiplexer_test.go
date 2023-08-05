package quic

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Multiplexer", func() {
	It("adds new packet conns", func() {
		conn1 := NewMockPacketConn(mockCtrl)
		conn1.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234})
		getMultiplexer().AddConn(conn1)
		conn2 := NewMockPacketConn(mockCtrl)
		conn2.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1235})
		getMultiplexer().AddConn(conn2)
	})

	It("panics when the same connection is added twice", func() {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}).Times(2)
		getMultiplexer().AddConn(conn)
		Expect(func() { getMultiplexer().AddConn(conn) }).To(Panic())
	})
})
