package quic

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type testConn struct {
	counter int
	net.PacketConn
}

var _ = Describe("Client Multiplexer", func() {
	It("adds a new packet conn ", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 8, nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("recognizes when the same connection is added twice", func() {
		pconn := newMockPacketConn()
		pconn.addr = &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
		conn := testConn{PacketConn: pconn}
		_, err := getMultiplexer().AddConn(conn, 8, nil)
		Expect(err).ToNot(HaveOccurred())
		conn.counter++
		_, err = getMultiplexer().AddConn(conn, 8, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(getMultiplexer().(*connMultiplexer).conns).To(HaveLen(1))
	})

	It("errors when adding an existing conn with a different connection ID length", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 5, nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 6, nil)
		Expect(err).To(MatchError("cannot use 6 byte connection IDs on a connection that is already using 5 byte connction IDs"))
	})

	It("errors when adding an existing conn with a different stateless rest key", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 7, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, []byte("raboof"))
		Expect(err).To(MatchError("cannot use different stateless reset keys on the same packet conn"))
	})
})
