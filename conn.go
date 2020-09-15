package quic

import (
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type connection interface {
	ReadPacket() (*receivedPacket, error)
	WriteTo([]byte, net.Addr) (int, error)
	LocalAddr() net.Addr
	io.Closer
}

func wrapConn(pc net.PacketConn) (connection, error) {
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		return &basicConn{PacketConn: pc}, nil
	}
	return newConn(udpConn)
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
