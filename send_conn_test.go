package quic

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection (for sending packets)", func() {
	var (
		c          rawConn
		packetConn *MockPacketConn
		addr       net.Addr
	)

	BeforeEach(func() {
		addr = &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
		packetConn = NewMockPacketConn(mockCtrl)
		var err error
		c, err = wrapConn(packetConn)
		Expect(err).ToNot(HaveOccurred())
	})

	It("writes", func() {
		sc := newSendConn(c, addr, nil)
		packetConn.EXPECT().WriteTo([]byte("foobar"), addr)
		Expect(sc.Write([]byte("foobar"))).To(Succeed())
	})

	It("gets the remote address", func() {
		sc := newSendConn(c, addr, nil)
		Expect(sc.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("gets the local address", func() {
		sc := newSendConn(c, addr, nil)
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 0, 1),
			Port: 1234,
		}
		packetConn.EXPECT().LocalAddr().Return(addr)
		Expect(sc.LocalAddr()).To(Equal(addr))
	})

	It("gets the local address, when using OOB", func() {
		sc := newSendConn(c, addr, &packetInfo{addr: net.IPv4(127, 0, 0, 1)})
		packetConn.EXPECT().LocalAddr().Return(&net.UDPAddr{
			IP:   net.IPv4(192, 168, 0, 1),
			Port: 1234,
		})
		Expect(sc.LocalAddr()).To(Equal(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}))
	})

	It("closes", func() {
		sc := newSendConn(c, addr, nil)
		packetConn.EXPECT().Close()
		Expect(sc.Close()).To(Succeed())
	})
})
