//go:build windows

package quic

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/windows"
)

// TO DO: Check if these are correct
const (
	ecnMask       = 0x3 // Check pending
	oobBufferSize = 128 // Check pending

	IP_ECN          = 0x32 // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IP_ECN.html
	IPV6_ECN        = 0x32 // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IPV6_ECN.html
	IP_RECVTOS      = 0x28 // https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/ws2ipdef.h
	IP_RECVECN      = 0x32 // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IP_RECVECN.html
	IPV6_RECVECN    = 0x32 // https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IPV6_RECVECN.html
	IPV6_RECVTCLASS = 0x28 // https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/ws2ipdef.h
)

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func isECNDisabledUsingEnv() bool {
	disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN"))
	return err == nil && disabled
}

type oobConn struct {
	OOBCapablePacketConn
	cap connCapabilities
}

var _ rawConn = &oobConn{}

func newConn(c OOBCapablePacketConn, supportsDF bool) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var needsPacketInfo bool
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}
	// rawConn may be IPv4, IPv6 or both.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errECNIPv4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_RECVECN, 1)
		errECNIPv6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_RECVECN, 1)

		if needsPacketInfo {
			errPIIPv4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1)
			errPIIPv6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}

	oobConn := &oobConn{
		OOBCapablePacketConn: c,
		cap: connCapabilities{
			DF:  supportsDF,
			GSO: isGSOEnabled(rawConn),
			ECN: isECNEnabled(),
		},
	}

	return oobConn, nil
}

var invalidCmsgOnceV4, invalidCmsgOnceV6 sync.Once

func (c *oobConn) ReadPacket() (receivedPacket, error) {
	buf := getPacketBuffer()
	buf.Data = buf.Data[:protocol.MaxPacketBufferSize]
	oobData := make([]byte, oobBufferSize)
	n, oobn, _, addr, err := c.OOBCapablePacketConn.ReadMsgUDP(buf.Data, oobData)
	if n == 0 || err != nil {
		return receivedPacket{}, err
	}

	data := oobData[:oobn]
	p := receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buf.Data[:n],
		buffer:     buf,
	}
	for len(data) > 0 {
		hdr, body, remainder, err := ParseOneSocketControlMessage(data)
		if err != nil {
			return receivedPacket{}, err
		}
		if hdr.Level == windows.IPPROTO_IP {
			switch hdr.Type {
			case IP_ECN:
				// TO DO: Check
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
			case windows.IP_PKTINFO:
				ip, ifIndex, ok := parseIPv4PktInfo(body)
				if ok {
					p.info.addr = ip
					p.info.ifIndex = ifIndex
				} else {
					invalidCmsgOnceV4.Do(func() {
						log.Printf("Received invalid IPv4 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		if hdr.Level == windows.IPPROTO_IPV6 {
			switch hdr.Type {
			case IPV6_ECN:
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
			case windows.IPV6_PKTINFO:
				// struct in6_pktinfo {
				// 	IN6_ADDR ipi6_addr;
				// 	ULONG    ipi6_ifindex;
				// };
				if len(body) == 20 {
					p.info.addr = netip.AddrFrom16(*(*[16]byte)(body[:16])).Unmap()
					p.info.ifIndex = binary.LittleEndian.Uint32(body[16:])
				} else {
					invalidCmsgOnceV6.Do(func() {
						log.Printf("Received invalid IPv6 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		data = remainder
	}
	return p, nil
}

// WritePacket writes a new packet.
func (c *oobConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	oob := packetInfoOOB
	if gsoSize > 0 {
		if !c.capabilities().GSO {
			panic("GSO disabled")
		}
		oob = appendUDPSegmentSizeMsg(oob, uint32(gsoSize)) // WritePacket expects uint16, but windows needs uint32
	}
	if ecn != protocol.ECNUnsupported {
		if !c.capabilities().ECN {
			panic("tried to send an ECN-marked packet although ECN is disabled")
		}
		if remoteUDPAddr, ok := addr.(*net.UDPAddr); ok {
			if remoteUDPAddr.IP.To4() != nil {
				oob = appendIPv4ECNMsg(oob, ecn)
			} else {
				oob = appendIPv6ECNMsg(oob, ecn)
			}
		}
	}
	n, _, err := c.OOBCapablePacketConn.WriteMsgUDP(b, oob, addr.(*net.UDPAddr))
	return n, err
}

func (c *oobConn) capabilities() connCapabilities {
	return c.cap
}

func appendIPv4ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4 // Expects a c_int, using int32
	b = append(b, make([]byte, cmsgSpace(dataLen))...)
	h := (*Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = windows.IPPROTO_IP
	h.Type = IP_ECN
	h.SetLen(cmsgLen(dataLen))

	offset := startLen + int(cmsgLen(0))
	*(*int32)(unsafe.Pointer(&b[offset])) = int32(val.ToHeaderBits())
	return b
}

func appendIPv6ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4
	b = append(b, make([]byte, cmsgSpace(dataLen))...)
	h := (*Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = windows.IPPROTO_IPV6

	h.Type = IPV6_ECN
	h.Len = cmsgLen(dataLen)

	offset := startLen + int(cmsgLen(0))
	b[offset] = val.ToHeaderBits()
	return b
}

type packetInfo struct {
	addr    netip.Addr
	ifIndex uint32
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.addr.Is4() {
		ip := info.addr.As4()
		// typedef struct in_pktinfo {
		// 	IN_ADDR ipi_addr;
		// 	ULONG   ipi_ifindex;
		// } IN_PKTINFO, *PIN_PKTINFO;
		cm := ipv4.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	} else if info.addr.Is6() {
		ip := info.addr.As16()
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		cm := ipv6.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	}
	return nil
}
