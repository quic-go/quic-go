package quic

import (
	"io"
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type connection interface {
	ReadPacket() (*receivedPacket, error)
	WriteTo([]byte, net.Addr) (int, error)
	LocalAddr() net.Addr
	io.Closer
}

type ecnCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

var _ ecnCapablePacketConn = (UDPConn)(nil)
var _ ecnCapablePacketConn = &net.UDPConn{}

func wrapConn(pc net.PacketConn) (connection, error) {
	c, ok := pc.(ecnCapablePacketConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		return &basicConn{PacketConn: pc}, nil
	}
	return newConn(c)
}

type basicConn struct {
	net.PacketConn
}

var _ connection = &basicConn{}

func (c *basicConn) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	n, addr, err := c.PacketConn.ReadFrom(buffer.Data)
	if err != nil {
		return nil, err
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}
