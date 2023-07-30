package quic

import (
	"net"
	"net/netip"

	"github.com/quic-go/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

	if platformSupportsGSO {
		It("writes with GSO", func() {
			rawConn := NewMockRawConn(mockCtrl)
			rawConn.EXPECT().LocalAddr()
			rawConn.EXPECT().capabilities().Return(connCapabilities{GSO: true}).AnyTimes()
			c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
			rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any()).Do(func(_ []byte, _ net.Addr, oob []byte) {
				msg := appendUDPSegmentSizeMsg([]byte{}, 3)
				Expect(oob).To(Equal(msg))
			})
			Expect(c.Write([]byte("foobar"), 3)).To(Succeed())
		})

		It("disables GSO if writing fails", func() {
			rawConn := NewMockRawConn(mockCtrl)
			rawConn.EXPECT().LocalAddr()
			rawConn.EXPECT().capabilities().Return(connCapabilities{GSO: true}).AnyTimes()
			c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
			Expect(c.capabilities().GSO).To(BeTrue())
			gomock.InOrder(
				rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Any()).DoAndReturn(func(_ []byte, _ net.Addr, oob []byte) (int, error) {
					msg := appendUDPSegmentSizeMsg([]byte{}, 3)
					Expect(oob).To(Equal(msg))
					return 0, errGSO
				}),
				rawConn.EXPECT().WritePacket([]byte("foo"), remoteAddr, gomock.Len(0)).Return(3, nil),
				rawConn.EXPECT().WritePacket([]byte("bar"), remoteAddr, gomock.Len(0)).Return(3, nil),
			)
			Expect(c.Write([]byte("foobar"), 3)).To(Succeed())
			Expect(c.capabilities().GSO).To(BeFalse()) // GSO support is now disabled
			// make sure we actually enforce that
			Expect(func() { c.Write([]byte("foobar"), 3) }).To(PanicWith("inconsistent packet size (6 vs 3)"))
		})
	} else {
		It("writes without GSO", func() {
			remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 100, 200), Port: 1337}
			rawConn := NewMockRawConn(mockCtrl)
			rawConn.EXPECT().LocalAddr()
			rawConn.EXPECT().capabilities()
			c := newSendConn(rawConn, remoteAddr, packetInfo{}, utils.DefaultLogger)
			rawConn.EXPECT().WritePacket([]byte("foobar"), remoteAddr, gomock.Len(0))
			Expect(c.Write([]byte("foobar"), 6)).To(Succeed())
		})
	}
})
