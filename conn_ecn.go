// +build !windows

package quic

import (
	"errors"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const ecnMask uint8 = 0x3

type ecnConn struct {
	ECNCapablePacketConn
	oobBuffer []byte
}

var _ connection = &ecnConn{}

func newConn(c ECNCapablePacketConn) (*ecnConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errIPv4, errIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errIPv4 = setRECVTOS(fd)
	}); err != nil {
		return nil, err
	}
	if err := rawConn.Control(func(fd uintptr) {
		errIPv6 = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVTCLASS, 1)
	}); err != nil {
		return nil, err
	}
	switch {
	case errIPv4 == nil && errIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errIPv4 == nil && errIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errIPv4 != nil && errIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errIPv4 != nil && errIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	return &ecnConn{
		ECNCapablePacketConn: c,
		oobBuffer:            make([]byte, 128),
	}, nil
}

func (c *ecnConn) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	c.oobBuffer = c.oobBuffer[:cap(c.oobBuffer)]
	n, oobn, _, addr, err := c.ECNCapablePacketConn.ReadMsgUDP(buffer.Data, c.oobBuffer)
	if err != nil {
		return nil, err
	}
	ctrlMsgs, err := syscall.ParseSocketControlMessage(c.oobBuffer[:oobn])
	if err != nil {
		return nil, err
	}
	var ecn protocol.ECN
	for _, ctrlMsg := range ctrlMsgs {
		if ctrlMsg.Header.Level == syscall.IPPROTO_IP && ctrlMsg.Header.Type == msgTypeIPTOS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
		if ctrlMsg.Header.Level == syscall.IPPROTO_IPV6 && ctrlMsg.Header.Type == syscall.IPV6_TCLASS {
			ecn = protocol.ECN(ctrlMsg.Data[0] & ecnMask)
			break
		}
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		ecn:        ecn,
		buffer:     buffer,
	}, nil
}
