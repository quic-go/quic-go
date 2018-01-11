package handshake

import (
	"net"
	"time"

	"github.com/bifurcation/mint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockConn struct {
	remoteAddr net.Addr
}

var _ net.Conn = &mockConn{}

func (c *mockConn) Read([]byte) (int, error)         { panic("not implemented") }
func (c *mockConn) Write([]byte) (int, error)        { panic("not implemented") }
func (c *mockConn) Close() error                     { panic("not implemented") }
func (c *mockConn) LocalAddr() net.Addr              { panic("not implemented") }
func (c *mockConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *mockConn) SetReadDeadline(time.Time) error  { panic("not implemented") }
func (c *mockConn) SetWriteDeadline(time.Time) error { panic("not implemented") }
func (c *mockConn) SetDeadline(time.Time) error      { panic("not implemented") }

var callbackReturn bool
var mockCallback = func(net.Addr, *Cookie) bool {
	return callbackReturn
}

var _ = Describe("Cookie Handler", func() {
	var ch *CookieHandler
	var conn *mint.Conn

	BeforeEach(func() {
		callbackReturn = false
		var err error
		ch, err = NewCookieHandler(mockCallback)
		Expect(err).ToNot(HaveOccurred())
		addr := &net.UDPAddr{IP: net.IPv4(42, 43, 44, 45), Port: 46}
		conn = mint.NewConn(&mockConn{remoteAddr: addr}, &mint.Config{}, false)
	})

	It("generates and validates a token", func() {
		cookie, err := ch.Generate(conn)
		Expect(err).ToNot(HaveOccurred())
		Expect(ch.Validate(conn, cookie)).To(BeFalse())
		callbackReturn = true
		Expect(ch.Validate(conn, cookie)).To(BeTrue())
	})

	It("doesn't generate a token if the callback says so", func() {
		callbackReturn = true
		cookie, err := ch.Generate(conn)
		Expect(err).ToNot(HaveOccurred())
		Expect(cookie).To(BeNil())
	})

	It("correctly handles a token that it can't decode", func() {
		cookie := []byte("unparseable cookie")
		Expect(ch.Validate(conn, cookie)).To(BeFalse())
	})
})
