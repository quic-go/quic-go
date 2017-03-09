package quic

import (
	"bytes"
	"io"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockPacketConn struct {
	addr          net.Addr
	dataToRead    []byte
	dataReadFrom  net.Addr
	readErr       error
	dataWritten   bytes.Buffer
	dataWrittenTo net.Addr
	closed        bool
}

func (c *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if c.dataToRead == nil { // block if there's no data
		time.Sleep(time.Hour)
		return 0, nil, io.EOF
	}
	n := copy(b, c.dataToRead)
	c.dataToRead = nil
	return n, c.dataReadFrom, nil
}
func (c *mockPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	c.dataWrittenTo = addr
	return c.dataWritten.Write(b)
}
func (c *mockPacketConn) Close() error                       { c.closed = true; return nil }
func (c *mockPacketConn) LocalAddr() net.Addr                { return c.addr }
func (c *mockPacketConn) SetDeadline(t time.Time) error      { panic("not implemented") }
func (c *mockPacketConn) SetReadDeadline(t time.Time) error  { panic("not implemented") }
func (c *mockPacketConn) SetWriteDeadline(t time.Time) error { panic("not implemented") }

var _ net.PacketConn = &mockPacketConn{}

var _ = Describe("Connection", func() {
	var c *conn
	var packetConn *mockPacketConn

	BeforeEach(func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 100, 200),
			Port: 1337,
		}
		packetConn = &mockPacketConn{}
		c = &conn{
			currentAddr: addr,
			pconn:       packetConn,
		}
	})

	It("writes", func() {
		err := c.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(packetConn.dataWritten.Bytes()).To(Equal([]byte("foobar")))
		Expect(packetConn.dataWrittenTo.String()).To(Equal("192.168.100.200:1337"))
	})

	It("reads", func() {
		packetConn.dataToRead = []byte("foo")
		packetConn.dataReadFrom = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1336}
		p := make([]byte, 10)
		n, raddr, err := c.Read(p)
		Expect(err).ToNot(HaveOccurred())
		Expect(raddr.String()).To(Equal("127.0.0.1:1336"))
		Expect(n).To(Equal(3))
		Expect(p[0:3]).To(Equal([]byte("foo")))
	})

	It("gets the remote address", func() {
		Expect(c.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("gets the local address", func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 0, 1),
			Port: 1234,
		}
		packetConn.addr = addr
		Expect(c.LocalAddr()).To(Equal(addr))
	})

	It("changes the remote address", func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 7331,
		}
		c.SetCurrentRemoteAddr(addr)
		Expect(c.RemoteAddr().String()).To(Equal(addr.String()))
	})

	It("closes", func() {
		err := c.Close()
		Expect(err).ToNot(HaveOccurred())
		Expect(packetConn.closed).To(BeTrue())
	})
})
