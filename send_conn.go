package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/utils"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write(b []byte, gsoSize uint16) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	capabilities() connCapabilities
}

type sconn struct {
	rawConn

	localAddr  net.Addr
	remoteAddr net.Addr

	logger utils.Logger

	packetInfoOOB []byte
	// If GSO enabled, and we receive a GSO error for this remote address, GSO is disabled.
	gotGSOError bool
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info packetInfo, logger utils.Logger) *sconn {
	localAddr := c.LocalAddr()
	if info.addr.IsValid() {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = info.addr.AsSlice()
			localAddr = &addrCopy
		}
	}

	oob := info.OOB()
	// add 32 bytes, so we can add the UDP_SEGMENT msg
	l := len(oob)
	oob = append(oob, make([]byte, 32)...)
	oob = oob[:l]
	return &sconn{
		rawConn:       c,
		localAddr:     localAddr,
		remoteAddr:    remote,
		packetInfoOOB: oob,
		logger:        logger,
	}
}

func (c *sconn) Write(p []byte, gsoSize uint16) error {
	_, err := c.WritePacket(p, c.remoteAddr, c.packetInfoOOB, gsoSize)
	if err != nil && isGSOError(err) {
		// disable GSO for future calls
		c.gotGSOError = true
		if c.logger.Debug() {
			c.logger.Debugf("GSO failed when sending to %s", c.remoteAddr)
		}
		// send out the packets one by one
		for len(p) > 0 {
			l := len(p)
			if l > int(gsoSize) {
				l = int(gsoSize)
			}
			if _, err := c.WritePacket(p[:l], c.remoteAddr, c.packetInfoOOB, 0); err != nil {
				return err
			}
			p = p[l:]
		}
		return nil
	}
	return err
}

func (c *sconn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if capabilities.GSO {
		capabilities.GSO = !c.gotGSOError
	}
	return capabilities
}

func (c *sconn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *sconn) LocalAddr() net.Addr  { return c.localAddr }
