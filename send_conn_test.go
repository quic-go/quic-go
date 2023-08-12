package quic

import (
	"net"
	"net/netip"
	"runtime"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

// Only if appendUDPSegmentSizeMsg actually appends a message (and isn't only a stub implementation),
// GSO is actually supported on this platform.
var platformSupportsGSO = len(appendUDPSegmentSizeMsg([]byte{}, 1337)) > 0

var _ = Describe("Connection (for sending packets)", func() {
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}

	It("gets the local and remote addresses", func() {
		localAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1234}
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr().Return(localAddr)
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		Expect(c.LocalAddr().String()).To(Equal("192.168.0.1:1234"))
		Expect(c.RemoteAddr().String()).To(Equal("192.168.100.200:1337"))
	})

	It("uses the local address from the packet info", func() {
		localAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1234}
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr().Return(localAddr)
		c := newSendConn(rawConn, remoteAddr, packetInfo{addr: netip.AddrFrom4([4]byte{127, 0, 0, 42})}, utils.DefaultLogger)
		Expect(c.LocalAddr().String()).To(Equal("127.0.0.42:1234"))
	})

	// We're not using an OOB conn on windows, and packetInfo.OOB() always returns an empty slice.
	if runtime.GOOS != "windows" {
		It("sets the OOB", func() {
			rawConn := NewMockRawConn(mockCtrl)
			rawConn.EXPECT().LocalAddr()
			rawConn.EXPECT().capabilities().AnyTimes()
			pi := packetInfo{addr: netip.IPv6Loopback()}
			Expect(pi.OOB()).ToNot(BeEmpty())
			c := newSendConn(rawConn, remoteAddr, pi, utils.DefaultLogger)
			rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, pi.OOB(), uint16(0), protocol.ECT1)
			Expect(c.Write([]byte("foobar"), 0, protocol.ECT1)).To(Succeed())
		})
	}

	It("writes", func() {
		rawConn := NewMockRawConn(mockCtrl)
		rawConn.EXPECT().LocalAddr()
		rawConn.EXPECT().capabilities().AnyTimes()
		c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
		rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), uint16(3), protocol.ECNCE)
		Expect(c.Write([]byte("foobar"), 3, protocol.ECNCE)).To(Succeed())
	})

	if platformSupportsGSO {
		It("disables GSO if sending fails", func() {
			rawConn := NewMockRawConn(mockCtrl)
			rawConn.EXPECT().LocalAddr()
			rawConn.EXPECT().capabilities().Return(connCapabilities{GSO: true}).AnyTimes()
			c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
			Expect(c.capabilities().GSO).To(BeTrue())
			gomock.InOrder(
				rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any(), uint16(4), protocol.ECNCE).Return(0, errGSO),
				rawConn.EXPECT().WritePacket([]byte("foob"), remoteAddr, gomock.Any(), uint16(0), protocol.ECNCE).Return(4, nil),
				rawConn.EXPECT().WritePacket([]byte("ar"), remoteAddr, gomock.Any(), uint16(0), protocol.ECNCE).Return(2, nil),
			)
			Expect(c.Write([]byte("foobar"), 4, protocol.ECNCE)).To(Succeed())
			Expect(c.capabilities().GSO).To(BeFalse())
		})
	}
})
