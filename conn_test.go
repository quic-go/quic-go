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
	dataWritten   bytes.Buffer
	dataWrittenTo net.Addr
	closed        bool
}

func (c *mockPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
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

	BeforeEach(func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 100, 200),
			Port: 1337,
		}
		c = &conn{
			currentAddr: addr,
			pconn:       &mockPacketConn{},
		}
	})

	It("writes", func() {
		err := c.write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(c.pconn.(*mockPacketConn).dataWritten.Bytes()).To(Equal([]byte("foobar")))
		Expect(c.pconn.(*mockPacketConn).dataWrittenTo.String()).To(Equal("192.168.100.200:1337"))
	})

	It("gets the remote address", func() {
		Expect(c.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("changes the remote address", func() {
		addr := &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 7331,
		}
		c.setCurrentRemoteAddr(addr)
		Expect(c.RemoteAddr().String()).To(Equal(addr.String()))
	})
})
