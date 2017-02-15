package quic

import (
	"net"
	"sync"
)

type connection interface {
	write([]byte) error
	setCurrentRemoteAddr(net.Addr)
	RemoteAddr() net.Addr
}

type conn struct {
	mutex sync.RWMutex

	pconn       net.PacketConn
	currentAddr net.Addr
}

var _ connection = &conn{}

func (c *conn) write(p []byte) error {
	_, err := c.pconn.WriteTo(p, c.currentAddr)
	return err
}

func (c *conn) setCurrentRemoteAddr(addr net.Addr) {
	c.mutex.Lock()
	c.currentAddr = addr
	c.mutex.Unlock()
}

func (c *conn) RemoteAddr() net.Addr {
	c.mutex.RLock()
	addr := c.currentAddr
	c.mutex.RUnlock()
	return addr
}
