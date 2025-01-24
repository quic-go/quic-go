//go:build windows

package quic

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	GSO_SIZE          = 1500
	UDP_SEND_MSG_SIZE = windows.UDP_SEND_MSG_SIZE
)

const batchSize = 8 // TO DO: Check if this is correct and works for windows too.

// TO DO: Check what this option (SNDBUF, RCVBUF) does when I try to set something above "max".

func forceSetReceiveBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, bytes)
	}); err != nil {
		return err
	}
	return serr
}

func forceSetSendBuffer(c syscall.RawConn, bytes int) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, bytes)
	}); err != nil {
		return err
	}
	return serr
}

func appendUDPSegmentSizeMsg([]byte, uint16) []byte { return nil }

func parseIPv4PktInfo(body []byte) (ip netip.Addr, ifIndex uint32, ok bool) {
	// 	struct in_pktinfo {
	// 		IN_ADDR ipi_addr;
	// 		ULONG   ipi_ifindex;
	// 	  } ;

	// Check if the input byte slice has exactly 8 bytes (size of struct in_pktinfo)
	if len(body) != 8 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(*(*[4]byte)(body[:4])), binary.LittleEndian.Uint32(body), true
}

func isGSOEnabled(conn syscall.RawConn) bool {
	gsoSegmentSize := getMaxGSOSegments()
	if gsoSegmentSize == 512 {
		return true
	}
	return false
}

// TO DO: Implement
func isECNEnabled() bool {
	return false
}

// I'm unable to find windows' response upon a failure caused related to GSO. TO DO
// Quinn just checks for GSO support using isGSOEnabled, nothing else.
func isGSOError(error) bool {
	return false
}

// This was written for linux, not applicable to windows.
func isPermissionError(err error) bool { return false }

// return the maximum number of GSO segments that can be sent
// if GSO is not supported, return 1
// if GSO is supported, return 512
func getMaxGSOSegments() int {
	// On Windows, GSO is supported if UDP_SEND_MSG_SIZE socket option is available
	// We can check this by trying to set it on a dummy socket
	dummy, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return 1
	}
	defer syscall.CloseHandle(dummy)

	err = syscall.SetsockoptInt(dummy, windows.IPPROTO_UDP, windows.UDP_SEND_MSG_SIZE, GSO_SIZE)
	if err != nil {
		return 1
	}
	return 512
}

// https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/ws2def.h#L726
type Cmsghdr struct {
	Len   uintptr
	Level int32
	Type  int32
}

func (cmsghdr Cmsghdr) Align() int {
	return reflect.TypeOf(cmsghdr).Align()
}

func (cmsghdr Cmsghdr) Size() uintptr {
	return reflect.TypeOf(cmsghdr).Size()
}

func (cmsghdr Cmsghdr) cmsgLen(length uintptr) uintptr {
	return cmsgDataAlign(cmsghdr.Size()) + length
}

func (cmsghdr *Cmsghdr) cmsgSpace(length uintptr) uintptr {
	return cmsgDataAlign(cmsghdr.Size() + cmsgHdrAlign(length))
}

func cmsgHdrAlign(len uintptr) uintptr {
	var cmsghdr Cmsghdr
	align := cmsghdr.Align()
	return (len + uintptr(align) - 1) & ^(uintptr(align) - 1)
}

func cmsgDataAlign(len uintptr) uintptr {
	var uint uintptr
	alignPointer := reflect.TypeOf(uint).Align()
	return (len + uintptr(alignPointer) - 1) & ^(uintptr(alignPointer) - 1)
}

// ParseOneSocketControlMessage parses a single socket control message from b, returning the message header,
// message data (a slice of b), and the remainder of b after that single message.
// When there are no remaining messages, len(remainder) == 0.
func ParseOneSocketControlMessage(b []byte) (hdr Cmsghdr, data []byte, remainder []byte, err error) {
	h, dbuf, err := socketControlMessageHeaderAndData(b)
	if err != nil {
		return Cmsghdr{}, nil, nil, err
	}
	if i := int(cmsgDataAlign(h.Len)); i < len(b) {
		remainder = b[i:]
	}
	return *h, dbuf, remainder, nil
}

func socketControlMessageHeaderAndData(b []byte) (*Cmsghdr, []byte, error) {
	h := (*Cmsghdr)(unsafe.Pointer(&b[0]))
	var cmsghdr Cmsghdr
	if h.Len < cmsghdr.Size() || uint64(h.Len) > uint64(len(b)) {
		return nil, nil, syscall.EINVAL
	}
	return h, b[cmsgDataAlign(cmsghdr.Size()):h.Len], nil
}
