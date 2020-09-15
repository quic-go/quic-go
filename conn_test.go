package quic

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Basic Conn Test", func() {
	It("reads a packet", func() {
		c := newMockPacketConn()
		addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}
		c.dataReadFrom = addr
		c.dataToRead <- []byte("foobar")

		conn, err := wrapConn(c)
		Expect(err).ToNot(HaveOccurred())
		p, err := conn.ReadPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(p.data).To(Equal([]byte("foobar")))
		Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(100*time.Millisecond)))
		Expect(p.remoteAddr).To(Equal(addr))
	})
})
