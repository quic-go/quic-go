package quic

import (
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

type qmuxSendConn struct {
	conn net.Conn
}

var _ sendConn = &qmuxSendConn{}

func (c *qmuxSendConn) Write(b []byte, _ uint16, _ protocol.ECN) error {
	n, err := c.conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *qmuxSendConn) WriteTo(b []byte, _ net.Addr, _ packetInfo) error {
	return c.Write(b, 0, protocol.ECNUnsupported)
}

func (c *qmuxSendConn) Close() error { return c.conn.Close() }

// setWriteDeadline bounds writes to the underlying transport. It is used during connection
// teardown, so that a peer that stopped reading can't block closing indefinitely.
func (c *qmuxSendConn) setWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *qmuxSendConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *qmuxSendConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *qmuxSendConn) ChangeRemoteAddr(net.Addr, packetInfo) {}

func (c *qmuxSendConn) capabilities() connCapabilities { return connCapabilities{} }
