package quic

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection (for sending packets)", func() {
	var (
		c          sendConn
		packetConn *MockPacketConn
		addr       net.Addr
	)

	BeforeEach(func() {
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = NewMockPacketConn(mockCtrl)
		c = newSendPconn(packetConn, addr)
	})

	It("writes", func() {
		packetConn.EXPECT().WriteTo([]byte("foobar"), addr)
		Expect(c.Write([]byte("foobar"))).To(Succeed())
	})

	It("gets the remote address", func() {
		Expect(c.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("gets the local address", func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 0, 1),
			Port: 1234,
		}
		packetConn.EXPECT().LocalAddr().Return(addr)
		Expect(c.LocalAddr()).To(Equal(addr))
	})

	It("closes", func() {
		packetConn.EXPECT().Close()
		Expect(c.Close()).To(Succeed())
	})
})
