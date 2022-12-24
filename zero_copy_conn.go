package quic

import (
	"net"
	"time"
)

// ZeroCopyConn allows you to communicate with QUIC by reducing the number of
// copies to zero. Although still a PacketConn, the ReadFrom and WriteTo
// methods won't be invoked.
type ZeroCopyConn interface {
	net.PacketConn

	// BufferPool returns only one buffer pool interface for the duration
	// of the connection. This pool is used to request memory for
	// transmitting packets. However, packets read from ReadPacket() will
	// also be released through this pool.
	BufferPool() BufferPool

	// ReadPacket reads one packet from the underlying connection. The
	// buffer will be released when fully processed by the stack. It's
	// expected for this method to block until a packet becomes available.
	// There can be many concurrent calls to this method.
	ReadPacket() (int, []byte, int, net.Addr, error)

	// WritePacket writes (or submits) the tagged buffer for writing.
	// Expect for the buffer to be released soon after this method
	// finishes, but take care of returning the buffer to the pool only
	// after actual transmission has occurred.
	WritePacket(buf []byte, tag int, addr net.Addr) (int, error)
}

type basicZeroCopyConn struct {
	ZeroCopyConn

	pool *packetBufferPool
}

func (c *basicZeroCopyConn) BufferPool() *packetBufferPool {
	return nil
}

func (c *basicZeroCopyConn) ReadPacket() (*receivedPacket, error) {
	n, data, tag, addr, err := c.ZeroCopyConn.ReadPacket()
	if err != nil {
		return nil, err
	}

	if tag == -1 {
		panic("quic: a zero copy connection must not read packets with a -1 tag")
	}

	buffer := packetPool.Get().(*packetBuffer)
	buffer.pool = c.ZeroCopyConn.BufferPool()
	buffer.Data = data
	buffer.Tag = tag

	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       data[:n],
		buffer:     buffer,
	}, nil
}

func (c *basicZeroCopyConn) WritePacket(b []byte, tag int, addr net.Addr, _ []byte) (int, error) {
	return c.ZeroCopyConn.WritePacket(b, tag, addr)
}
